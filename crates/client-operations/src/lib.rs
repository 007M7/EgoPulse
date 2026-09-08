#![forbid(unsafe_code)]

#[allow(
    dead_code,
    reason = "R9B.2 domain drivers consume this runtime-agnostic reducer in the follow-up slice"
)]
mod governed_state;

#[allow(
    dead_code,
    reason = "R9B.2a source/session conversion follows the shared driver classifiers"
)]
mod governed_state_driver;

mod harness_content_driver;

pub use governed_state::{
    GovernedApprovalDomainPosition, GovernedApprovalDomainState, GovernedApprovalState,
    GovernedStateComposite, GovernedStateDomain, GovernedStateDomainPhase, GovernedStateReason,
    GovernedTaskDomainPosition, GovernedTaskDomainState,
};
pub use governed_state_driver::{
    GovernedStateSession, GovernedStateSessionStartError, GovernedStateShutdown,
    GovernedStateUpdate,
};
pub use harness_content_driver::{
    ClientHarnessContentError, HarnessContentDriver, HarnessContentFilter, HarnessContentSession,
    HarnessContentUpdate, HarnessContentUpdateKind,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    time::SystemTime,
};

use egopulse_client_kernel::{ClientKernel, KernelError, SnapshotStreamTracker, StreamApply};
use egopulse_domain_contracts::{
    context_revoke::ContextRevokeSemanticRequest,
    memory::{WORK_MEMORY_MAX_RESULTS, WORK_MEMORY_MAX_SELECTED_CONTENT_BYTES},
    v01::egopulse::{
        artifact::v1::{ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding},
        collaboration::v1::{AttemptStatus, RecoveryClass, RunStatus, StepStatus},
        common::v1::CommandMetadata,
        harness::v1::ApprovalDecision,
        localapi::v1::{
            AvailableActionKind, ClientRequestMetadata, ClientSurface, ConfirmWorkRequest,
            ConfirmWorkResponse, ContextGovernanceState, ContextMutationCommand,
            ContextRevokeReceipt, CreateFounderSupportingMaterialRequest,
            CreateFounderSupportingMaterialResponse, DecideHarnessApprovalRequest,
            DecideHarnessApprovalResponse, EvidenceGraphView, ExecuteContextMutationRequest,
            ExecuteContextMutationResponse, ExecuteFounderVerdictRequest,
            ExecuteFounderVerdictResponse, ExecuteTaskCommandRequest, ExecuteTaskCommandResponse,
            GetEvidenceGraphRequest, GetEvidenceGraphResponse, GetHarnessApprovalViewRequest,
            GetHarnessApprovalViewResponse, GetProjectionStatusRequest, GetTaskViewRequest,
            GetTaskViewResponse, HarnessApprovalAuthorityResult, HarnessApprovalView,
            HarnessApprovalViewStreamFrame, ListHarnessApprovalViewsRequest,
            ListHarnessApprovalViewsResponse, ListTaskViewsRequest, ListTaskViewsResponse,
            ListWorkCapabilitiesRequest, ListWorkCapabilitiesResult, LocalApiError,
            PrepareWorkRequest, PrepareWorkResponse, ProjectionAwaitToken, ProjectionHealth,
            ProjectionMetadata, ProjectionPosition, RevokeContextSnapshotCommand,
            SetDefaultWorkCapabilityRequest, SourceDomain, SourceRevision, StreamFrameKind,
            TaskView, TaskViewStreamFrame, UseDefaultWorkCapability,
            WatchHarnessApprovalViewsRequest, WatchTaskViewsRequest, WorkCapabilityAvailability,
            WorkCapabilityPreferenceReceipt, WorkCapabilitySelectionSource, WorkCapabilityView,
            WorkMemoryMode, WorkPreparationPreview, WorkSourceRequest, context_mutation_command,
            execute_context_mutation_response, get_evidence_graph_response,
            get_harness_approval_view_response, get_task_view_response,
            list_work_capabilities_response, prepare_work_request,
            set_default_work_capability_response,
        },
        policy::v1::{
            HarnessApprovalDecisionStateKind, IssueHarnessApprovalDecisionCommand,
            PolicyDecisionCommand, PolicyDecisionErrorCode, policy_decision_command,
        },
        task::v1::{
            ApplyFounderVerdictCommand, TaskCommand, TaskCommandResult, TaskErrorCode,
            TaskEventKind, TaskSnapshot, TaskStatus as DomainTaskStatus, task_command,
            task_command_result,
        },
        verdict::v1::{
            ConfirmationClass, CreateFounderSupportingMaterialCommand, FounderSupportingMaterial,
            FounderSupportingMaterialCoverage, FounderSupportingMaterialReceipt,
            FounderSupportingMaterialRole, FounderVerdictDecision, FounderVerdictStateKind,
            IssueFounderVerdictCommand, ReworkDirective, RiskAcceptance, RiskCategory,
            VerdictCommand, VerdictCommandResult, VerdictErrorCode, VerdictEventKind, VerdictScope,
            verdict_command,
        },
        verification::v1::VerificationConclusion,
    },
    work_capability::validate_work_capability_route_binding,
};
use egopulse_local_api::{LocalApiClient, LocalApiConnection, LocalIpcAddress};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const EXECUTE_CONTEXT_MUTATION_RPC: &str = "LocalCommandGatewayService/ExecuteContextMutation";
const REVOKE_CONTEXT_SNAPSHOT_COMMAND: &str = "revoke_context_snapshot";
const CONTEXT_REVOKE_IDEMPOTENCY_SCOPE: &str = "context-revoke";
const WATCH_TASK_VIEWS_RPC: &str = "LocalReadModelService/WatchTaskViews";
const LIST_HARNESS_APPROVAL_VIEWS_RPC: &str = "LocalReadModelService/ListHarnessApprovalViews";
const WATCH_HARNESS_APPROVAL_VIEWS_RPC: &str = "LocalReadModelService/WatchHarnessApprovalViews";
const GET_HARNESS_APPROVAL_VIEW_RPC: &str = "LocalReadModelService/GetHarnessApprovalView";
const DECIDE_HARNESS_APPROVAL_RPC: &str = "LocalCommandGatewayService/DecideHarnessApproval";
const ISSUE_HARNESS_APPROVAL_DECISION_COMMAND: &str = "issue_harness_approval_decision";
const APPROVAL_DECISION_IDEMPOTENCY_SCOPE: &str = "approval-decision";
const GUIDED_APPROVAL_IDEMPOTENCY_DOMAIN: &[u8] = b"egopulse/guided-approval/v1\0";
const GET_TASK_VIEW_RPC: &str = "LocalReadModelService/GetTaskView";
const GET_EVIDENCE_GRAPH_RPC: &str = "LocalReadModelService/GetEvidenceGraph";
const PREPARE_WORK_RPC: &str = "LocalCommandGatewayService/PrepareWork";
const CONFIRM_WORK_RPC: &str = "LocalCommandGatewayService/ConfirmWork";
const LIST_WORK_CAPABILITIES_RPC: &str = "LocalCommandGatewayService/ListWorkCapabilities";
const SET_DEFAULT_WORK_CAPABILITY_RPC: &str = "LocalCommandGatewayService/SetDefaultWorkCapability";
const LIST_TASK_VIEWS_RPC: &str = "LocalReadModelService/ListTaskViews";
const GOVERNED_TASK_BASELINE_PAGE_SIZE: u32 = 100;
const GOVERNED_TASK_BASELINE_MAX_PAGES: usize = 100;
const GOVERNED_TASK_BASELINE_MAX_VIEWS: usize = 1_000;
const GOVERNED_TASK_MAX_IDENTIFIER_BYTES: usize = 256;
const APPROVAL_WATCH_BASELINE_PAGE_SIZE: u32 = 100;
const APPROVAL_WATCH_BASELINE_MAX_PAGES: usize = 100;
const APPROVAL_WATCH_BASELINE_MAX_VIEWS: usize = 1_000;
const GUIDED_WORK_MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
const GUIDED_WORK_MAX_ROUTING_BYTES: usize = 4 * 1024;
const GUIDED_WORK_MAX_SOURCES: usize = 256;
const EXECUTE_FOUNDER_VERDICT_RPC: &str = "LocalCommandGatewayService/ExecuteFounderVerdict";
const ISSUE_FOUNDER_VERDICT_COMMAND: &str = "issue_founder_verdict";
const EXECUTE_TASK_COMMAND_RPC: &str = "LocalCommandGatewayService/ExecuteTaskCommand";
const APPLY_FOUNDER_VERDICT_COMMAND: &str = "apply_founder_verdict";
const GUIDED_FOUNDER_APPLY_SCOPE: &str = "guided-founder-decision/apply/v1";

mod founder_recovery;
mod recovery_store;
pub use founder_recovery::{
    DurableFounderDecisionAttempt, DurableFounderMaterialAttempt, DurableFounderMaterialRecovery,
    DurableFounderRecoveryError, DurableFounderVerdictAttempt, DurableFounderVerdictRecovery,
};

/// A local client that has completed the frozen session and contract handshake.
///
/// Surfaces own presentation and error policy; they do not own a second attach
/// protocol. All writes made from CLI, TUI, and Desktop start from this object.
pub struct ClientAttachment {
    pub connection: LocalApiConnection,
    pub kernel: ClientKernel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuidedApprovalDecision {
    AllowOnce,
    Deny,
    CancelAttempt,
}

impl GuidedApprovalDecision {
    fn wire_value(self) -> i32 {
        match self {
            Self::AllowOnce => ApprovalDecision::AllowOnce as i32,
            Self::Deny => ApprovalDecision::Deny as i32,
            Self::CancelAttempt => ApprovalDecision::CancelAttempt as i32,
        }
    }

    #[must_use]
    pub fn contract_name(self) -> &'static str {
        match self {
            Self::AllowOnce => "APPROVAL_DECISION_ALLOW_ONCE",
            Self::Deny => "APPROVAL_DECISION_DENY",
            Self::CancelAttempt => "APPROVAL_DECISION_CANCEL_ATTEMPT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidedApprovalDecisionInput {
    pub approval_request_id: String,
    pub decision: GuidedApprovalDecision,
    pub reason_code: String,
    pub confirmation_proof_ref: Option<String>,
    /// The Adapter-produced summary actually reviewed by the user. A positive
    /// decision must not silently rebind to a changed operation after refresh.
    pub reviewed_summary_digest_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum ClientGuidedApprovalDecisionError {
    #[error("client kernel rejected the guided approval decision: {0}")]
    Kernel(#[from] KernelError),
    #[error("guided approval decision input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("the requested Harness approval was not found")]
    NotFound,
    #[error("the latest Harness approval is not actionable")]
    NonActionable,
    #[error("local API guided approval transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the guided approval decision: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("Policy Decision Authority rejected the guided approval decision")]
    Authority {
        error_code: i32,
        safe_error_fingerprint: Option<String>,
    },
    #[error("guided approval protocol integrity failed: {0}")]
    Protocol(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidedApprovalDecisionResult {
    authority: HarnessApprovalAuthorityResult,
    await_token: Option<ProjectionAwaitToken>,
    projection_warning: Option<LocalApiError>,
    correlation_id: String,
}

impl GuidedApprovalDecisionResult {
    #[must_use]
    pub fn committed(&self) -> bool {
        self.authority.committed
    }

    #[must_use]
    pub fn replayed(&self) -> bool {
        self.authority.replayed
    }

    #[must_use]
    pub fn authority_decision_ref(&self) -> &str {
        &self.authority.authority_decision_ref
    }

    #[must_use]
    pub fn decision(&self) -> GuidedApprovalDecision {
        match ApprovalDecision::try_from(self.authority.decision)
            .expect("validated guided approval decision")
        {
            ApprovalDecision::AllowOnce => GuidedApprovalDecision::AllowOnce,
            ApprovalDecision::Deny => GuidedApprovalDecision::Deny,
            ApprovalDecision::CancelAttempt => GuidedApprovalDecision::CancelAttempt,
            ApprovalDecision::Unspecified => unreachable!("validated guided approval decision"),
        }
    }

    #[must_use]
    pub fn state_revision(&self) -> u64 {
        self.authority.state_revision
    }

    #[must_use]
    pub fn await_token(&self) -> Option<&ProjectionAwaitToken> {
        self.await_token.as_ref()
    }

    #[must_use]
    pub fn projection_warning(&self) -> Option<&LocalApiError> {
        self.projection_warning.as_ref()
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
}

#[derive(Clone, Debug)]
pub struct ProjectionSnapshot {
    pub metadata: ProjectionMetadata,
    pub tasks: Vec<TaskView>,
    pub approvals: Vec<HarnessApprovalView>,
}

#[derive(Debug, Error)]
pub enum ClientReadError {
    #[error("client kernel rejected the read: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the read: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("local API returned an incomplete response: {0}")]
    Protocol(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskResultReviewStage {
    Task,
    Evidence,
}

impl TaskResultReviewStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Evidence => "evidence",
        }
    }
}

#[derive(Debug, Error)]
pub enum ClientTaskResultReviewError {
    #[error("invalid projected result review input: {0}")]
    InvalidInput(&'static str),
    #[error("client kernel rejected the {stage:?} review stage: {source}")]
    Kernel {
        stage: TaskResultReviewStage,
        #[source]
        source: KernelError,
    },
    #[error("local API transport failed during the {stage:?} review stage: {detail}")]
    Transport {
        stage: TaskResultReviewStage,
        detail: String,
    },
    #[error("local API rejected the {stage:?} review stage: {error:?}")]
    Api {
        stage: TaskResultReviewStage,
        error: Box<LocalApiError>,
    },
    #[error("projected result review integrity failed during the {stage:?} stage: {detail}")]
    Integrity {
        stage: TaskResultReviewStage,
        detail: &'static str,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskResultReview {
    pub task_view: TaskView,
    pub evidence_graph: Option<EvidenceGraphView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuidedFounderVerdictSelection {
    Accept,
    Rework,
    Reject,
}

/// Caller-owned identity and confirmation material for a verdict built from a
/// current, trusted result-review snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct GuidedFounderVerdictInput {
    pub current_task_id: String,
    pub metadata: CommandMetadata,
    pub selection: GuidedFounderVerdictSelection,
    pub reason_code: String,
    pub confirmation_proof_ref: String,
    pub expires_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFounderSupportingMaterial {
    command: CreateFounderSupportingMaterialCommand,
    capsule: FounderSupportingMaterialTrustedCapsule,
    session_id: String,
    authenticated_principal_id: String,
}

impl PreparedFounderSupportingMaterial {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn authenticated_principal_id(&self) -> &str {
        &self.authenticated_principal_id
    }

    pub fn command(&self) -> &CreateFounderSupportingMaterialCommand {
        &self.command
    }

    pub fn capsule(&self) -> &FounderSupportingMaterialTrustedCapsule {
        &self.capsule
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FounderSupportingMaterialTrustedCapsule {
    pub review_lineage: LineageBinding,
    pub verdict_scope: VerdictScope,
    pub authenticated_founder_principal_id: String,
    pub material_id: String,
    pub role: FounderSupportingMaterialRole,
    pub body: String,
    pub coverage: Option<FounderSupportingMaterialCoverage>,
    pub canonical_payload: Vec<u8>,
    pub expected_payload_address: ContentAddress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedFounderSupportingMaterialReceipt {
    receipt: FounderSupportingMaterialReceipt,
    command: CreateFounderSupportingMaterialCommand,
    capsule: FounderSupportingMaterialTrustedCapsule,
}

/// A collection can contain only receipts returned by the authenticated
/// supporting-material submission path because the receipt constructor and
/// all fields remain private to this crate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FounderSupportingMaterialCollection {
    materials: Vec<ConfirmedFounderSupportingMaterialReceipt>,
}

impl FounderSupportingMaterialCollection {
    pub fn from_confirmed(
        materials: Vec<ConfirmedFounderSupportingMaterialReceipt>,
    ) -> Result<Self, ClientGuidedFounderVerdictError> {
        let mut material_ids = BTreeSet::new();
        let mut artifact_ids = BTreeSet::new();
        if materials.iter().any(|material| {
            !material_ids.insert(material.receipt.material_id.as_str())
                || !artifact_ids.insert(material.receipt.artifact_id.as_str())
        }) {
            return Err(ClientGuidedFounderVerdictError::InvalidInput(
                "confirmed supporting materials must have unique material and Artifact identities",
            ));
        }
        Ok(Self { materials })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.materials.is_empty()
    }
}

/// Exact caller-owned recovery state retained after a supporting-material
/// write may have reached the Authority. Neither the request metadata nor the
/// trusted review capsule is rebuilt on retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableFounderSupportingMaterial {
    request: CreateFounderSupportingMaterialRequest,
    prepared: PreparedFounderSupportingMaterial,
}

impl RecoverableFounderSupportingMaterial {
    pub fn request(&self) -> &CreateFounderSupportingMaterialRequest {
        &self.request
    }

    pub fn prepared(&self) -> &PreparedFounderSupportingMaterial {
        &self.prepared
    }
}

impl ConfirmedFounderSupportingMaterialReceipt {
    fn from_prepared(
        receipt: FounderSupportingMaterialReceipt,
        prepared: &PreparedFounderSupportingMaterial,
    ) -> Result<Self, ClientFounderSupportingMaterialError> {
        let command = &prepared.command;
        let capsule = &prepared.capsule;
        if receipt.canonical_payload.as_ref() != Some(&capsule.expected_payload_address) {
            return Err(ClientFounderSupportingMaterialError::UnconfirmedReceipt);
        }
        if !(receipt.committed || receipt.replayed)
            || receipt.material_id.trim().is_empty()
            || receipt.artifact_id.trim().is_empty()
            || receipt.command_id.trim().is_empty()
            || receipt.canonical_payload.is_none()
            || receipt.scope.is_none()
            || receipt.material_id != command.material_id
            || receipt.role != command.role
            || receipt.scope != command.scope
            || receipt.command_id
                != command
                    .metadata
                    .as_ref()
                    .map(|value| value.command_id.as_str())
                    .unwrap_or_default()
            || receipt.correlation_id
                != command
                    .metadata
                    .as_ref()
                    .map(|value| value.correlation_id.as_str())
                    .unwrap_or_default()
            || receipt.artifact_id != founder_supporting_material_artifact_id(&command.material_id)
        {
            return Err(ClientFounderSupportingMaterialError::UnconfirmedReceipt);
        }
        Ok(Self {
            receipt,
            command: command.clone(),
            capsule: capsule.clone(),
        })
    }

    pub fn receipt(&self) -> &FounderSupportingMaterialReceipt {
        &self.receipt
    }
}

#[derive(Debug, Error)]
pub enum ClientFounderSupportingMaterialError {
    #[error("supporting material recovery could not be saved; no request was sent")]
    RecoveryStorage,
    #[error("supporting material input is invalid")]
    InvalidInput,
    #[error("supporting material receipt is not committed or replayed with a sealed payload")]
    UnconfirmedReceipt,
    #[error("client kernel rejected supporting material RPC: {0}")]
    Kernel(#[from] KernelError),
    #[error("supporting material transport failed: {0}")]
    Transport(String),
    #[error("supporting material authority rejected the request")]
    Authority,
    #[error("supporting material write outcome is unknown")]
    Unknown {
        recovery: Box<RecoverableFounderSupportingMaterial>,
    },
}

pub struct FounderSupportingMaterialBuilder {
    capsule: FounderSupportingMaterialTrustedCapsule,
    session_id: String,
}

fn founder_supporting_material_artifact_id(material_id: &str) -> String {
    let mut framed = Vec::with_capacity(material_id.len() + 32);
    framed.extend_from_slice(&("founder-supporting-material".len() as u64).to_be_bytes());
    framed.extend_from_slice(b"founder-supporting-material");
    framed.extend_from_slice(&(material_id.len() as u64).to_be_bytes());
    framed.extend_from_slice(material_id.as_bytes());
    format!("founder-material-{}", hex::encode(Sha256::digest(framed)))
}

impl FounderSupportingMaterialBuilder {
    pub fn from_review(
        review: &TaskResultReview,
        session: &egopulse_client_kernel::SessionBinding,
        material_id: String,
        role: FounderSupportingMaterialRole,
        body: String,
        coverage: Option<FounderSupportingMaterialCoverage>,
    ) -> Result<Self, ClientFounderSupportingMaterialError> {
        if material_id.trim().is_empty()
            || body.trim().is_empty()
            || session.session_id.trim().is_empty()
            || session.authenticated_principal_id.trim().is_empty()
            || role == FounderSupportingMaterialRole::Unspecified
            || !supporting_material_coverage_is_valid(role, coverage.as_ref())
        {
            return Err(ClientFounderSupportingMaterialError::InvalidInput);
        }
        let task = review
            .task_view
            .task
            .as_ref()
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let current_task_id = task.task_id.clone();
        let (_, artifact_set_id) =
            validate_task_result_view(&review.task_view, &current_task_id)
                .map_err(|_| ClientFounderSupportingMaterialError::InvalidInput)?;
        let artifact_set_id =
            artifact_set_id.ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let graph = review
            .evidence_graph
            .as_ref()
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        validate_evidence_graph(&review.task_view, graph, &current_task_id, &artifact_set_id)
            .map_err(|_| ClientFounderSupportingMaterialError::InvalidInput)?;
        validate_founder_verdict_action(&review.task_view)
            .map_err(|_| ClientFounderSupportingMaterialError::InvalidInput)?;

        let task = review
            .task_view
            .task
            .as_ref()
            .expect("trusted result review contains a Task");
        let set = review
            .task_view
            .artifact_set
            .as_ref()
            .expect("trusted result review contains an ArtifactSet");
        let verification = review
            .task_view
            .verification
            .as_ref()
            .expect("trusted result review contains a Verification");
        if set.status != ArtifactSetStatus::Sealed as i32 {
            return Err(ClientFounderSupportingMaterialError::InvalidInput);
        }
        let artifact_set_manifest = set
            .canonical_manifest
            .clone()
            .filter(guided_verdict_content_address_is_complete)
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let verification_payload = verification
            .canonical_payload
            .clone()
            .filter(guided_verdict_content_address_is_complete)
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let acceptance_contract_ref = task
            .acceptance_contract_ref
            .clone()
            .filter(guided_verdict_contract_is_complete)
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let lineage = set
            .lineage
            .clone()
            .filter(result_lineage_is_complete)
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let scope = VerdictScope {
            task_id: task.task_id.clone(),
            task_revision: task.revision,
            work_revision: task.work_revision,
            artifact_set_id,
            artifact_set_manifest: Some(artifact_set_manifest),
            verification_artifact_id: verification.verification_artifact_id.clone(),
            verification_payload: Some(verification_payload),
            acceptance_contract_ref: Some(acceptance_contract_ref),
        };
        let payload = FounderSupportingMaterial {
            material_id: material_id.clone(),
            schema_version: 1,
            role: role as i32,
            scope: Some(scope.clone()),
            lineage: Some(lineage.clone()),
            authenticated_founder_principal_id: session.authenticated_principal_id.clone(),
            body: body.clone(),
            coverage: coverage.clone(),
        };
        let canonical_payload = payload.encode_to_vec();
        let expected_payload_address = ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: hex::encode(Sha256::digest(&canonical_payload)),
            byte_length: canonical_payload.len() as u64,
        };
        Ok(Self {
            capsule: FounderSupportingMaterialTrustedCapsule {
                review_lineage: lineage,
                verdict_scope: scope,
                authenticated_founder_principal_id: session.authenticated_principal_id.clone(),
                material_id,
                role,
                body,
                coverage,
                canonical_payload,
                expected_payload_address,
            },
            session_id: session.session_id.clone(),
        })
    }

    pub fn build(
        self,
        metadata: CommandMetadata,
    ) -> Result<PreparedFounderSupportingMaterial, ClientFounderSupportingMaterialError> {
        if !supporting_material_metadata_is_valid(&metadata, false) {
            return Err(ClientFounderSupportingMaterialError::InvalidInput);
        }
        let capsule = self.capsule;
        let authenticated_principal_id = capsule.authenticated_founder_principal_id.clone();
        let mut command = CreateFounderSupportingMaterialCommand {
            metadata: Some(metadata),
            material_id: capsule.material_id.clone(),
            scope: Some(capsule.verdict_scope.clone()),
            role: capsule.role as i32,
            body: capsule.body.clone(),
            coverage: capsule.coverage.clone(),
        };
        let supplied_digest = command
            .metadata
            .as_ref()
            .expect("metadata validated")
            .request_digest_sha256
            .clone();
        let digest = canonical_founder_material_request_digest(&command)
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        if !supplied_digest.is_empty() && supplied_digest != digest {
            return Err(ClientFounderSupportingMaterialError::InvalidInput);
        }
        command
            .metadata
            .as_mut()
            .expect("metadata validated")
            .request_digest_sha256 = digest;
        Ok(PreparedFounderSupportingMaterial {
            command,
            capsule,
            session_id: self.session_id,
            authenticated_principal_id,
        })
    }

    pub fn capsule(&self) -> &FounderSupportingMaterialTrustedCapsule {
        &self.capsule
    }
}

fn supporting_material_coverage_is_valid(
    role: FounderSupportingMaterialRole,
    coverage: Option<&FounderSupportingMaterialCoverage>,
) -> bool {
    let Some(coverage) = coverage else {
        return false;
    };
    let ids_are_valid = |ids: &[String]| {
        !ids.iter().any(|id| id.trim().is_empty())
            && ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
    };
    if !ids_are_valid(&coverage.discrepancy_ids) || !ids_are_valid(&coverage.unverified_item_ids) {
        return false;
    }
    let Ok(risk) = RiskCategory::try_from(coverage.risk_category) else {
        return false;
    };
    match role {
        FounderSupportingMaterialRole::ReworkRequiredChanges => risk == RiskCategory::Unspecified,
        FounderSupportingMaterialRole::RiskRationale
        | FounderSupportingMaterialRole::CompensatingControl => {
            risk != RiskCategory::Unspecified
                && (!coverage.discrepancy_ids.is_empty()
                    || !coverage.unverified_item_ids.is_empty())
        }
        FounderSupportingMaterialRole::Unspecified => false,
    }
}

fn supporting_material_metadata_is_valid(metadata: &CommandMetadata, sealed: bool) -> bool {
    !metadata.command_id.trim().is_empty()
        && !metadata.idempotency_key.trim().is_empty()
        && !metadata.idempotency_scope.trim().is_empty()
        && !metadata.correlation_id.trim().is_empty()
        && metadata
            .issued_at
            .as_ref()
            .is_some_and(guided_verdict_timestamp_is_valid)
        && if sealed {
            guided_verdict_digest_is_complete(&metadata.request_digest_sha256)
        } else {
            metadata.request_digest_sha256.is_empty()
                || guided_verdict_digest_is_complete(&metadata.request_digest_sha256)
        }
}

fn validate_prepared_founder_supporting_material(
    prepared: &PreparedFounderSupportingMaterial,
) -> Result<(), ClientFounderSupportingMaterialError> {
    let command = &prepared.command;
    let capsule = &prepared.capsule;
    let metadata = command
        .metadata
        .as_ref()
        .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
    if !supporting_material_metadata_is_valid(metadata, true)
        || canonical_founder_material_request_digest(command).as_deref()
            != Some(metadata.request_digest_sha256.as_str())
        || prepared.authenticated_principal_id.trim().is_empty()
        || prepared.authenticated_principal_id != capsule.authenticated_founder_principal_id
        || command.material_id != capsule.material_id
        || command.scope.as_ref() != Some(&capsule.verdict_scope)
        || command.role != capsule.role as i32
        || command.body != capsule.body
        || command.coverage != capsule.coverage
        || !supporting_material_coverage_is_valid(capsule.role, capsule.coverage.as_ref())
    {
        return Err(ClientFounderSupportingMaterialError::InvalidInput);
    }
    let scope = &capsule.verdict_scope;
    if scope.task_id != capsule.review_lineage.task_id
        || scope.task_revision < capsule.review_lineage.task_revision
        || scope.work_revision != capsule.review_lineage.work_revision
        || scope.artifact_set_id.trim().is_empty()
        || scope.verification_artifact_id.trim().is_empty()
        || scope
            .artifact_set_manifest
            .as_ref()
            .is_none_or(|address| !guided_verdict_content_address_is_complete(address))
        || scope
            .verification_payload
            .as_ref()
            .is_none_or(|address| !guided_verdict_content_address_is_complete(address))
        || scope
            .acceptance_contract_ref
            .as_ref()
            .is_none_or(|reference| !guided_verdict_contract_is_complete(reference))
        || !result_lineage_is_complete(&capsule.review_lineage)
    {
        return Err(ClientFounderSupportingMaterialError::InvalidInput);
    }
    let payload = FounderSupportingMaterial {
        material_id: capsule.material_id.clone(),
        schema_version: 1,
        role: capsule.role as i32,
        scope: Some(capsule.verdict_scope.clone()),
        lineage: Some(capsule.review_lineage.clone()),
        authenticated_founder_principal_id: capsule.authenticated_founder_principal_id.clone(),
        body: capsule.body.clone(),
        coverage: capsule.coverage.clone(),
    };
    let canonical_payload = payload.encode_to_vec();
    let expected_address = ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: hex::encode(Sha256::digest(&canonical_payload)),
        byte_length: canonical_payload.len() as u64,
    };
    if capsule.canonical_payload != canonical_payload
        || capsule.expected_payload_address != expected_address
    {
        return Err(ClientFounderSupportingMaterialError::InvalidInput);
    }
    Ok(())
}

async fn submit_founder_supporting_material_via<Send, SendFuture>(
    kernel: &ClientKernel,
    prepared: PreparedFounderSupportingMaterial,
    now: SystemTime,
    send: Send,
) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
where
    Send: FnOnce(CreateFounderSupportingMaterialRequest) -> SendFuture,
    SendFuture: Future<Output = Result<CreateFounderSupportingMaterialResponse, String>>,
{
    validate_prepared_founder_supporting_material(&prepared)?;
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    let _authorized = kernel.authorize_create_founder_supporting_material()?;
    if session.authenticated_principal_id != prepared.authenticated_principal_id
        || session.session_id != prepared.session_id
    {
        return Err(ClientFounderSupportingMaterialError::InvalidInput);
    }
    let metadata = prepared
        .command
        .metadata
        .as_ref()
        .expect("prepared supporting material metadata validated");
    let request = CreateFounderSupportingMaterialRequest {
        client: Some(kernel.request_metadata(
            Uuid::now_v7().to_string(),
            Some(metadata.correlation_id.clone()),
            now,
        )?),
        command: Some(prepared.command.clone()),
    };
    let recovery = RecoverableFounderSupportingMaterial { request, prepared };
    dispatch_founder_supporting_material(recovery, send).await
}

async fn retry_founder_supporting_material_via<Send, SendFuture>(
    kernel: &ClientKernel,
    recovery: &RecoverableFounderSupportingMaterial,
    send: Send,
) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
where
    Send: FnOnce(CreateFounderSupportingMaterialRequest) -> SendFuture,
    SendFuture: Future<Output = Result<CreateFounderSupportingMaterialResponse, String>>,
{
    let frozen = recovery.clone();
    let preflight: Result<(), ClientFounderSupportingMaterialError> = (|| {
        validate_prepared_founder_supporting_material(&frozen.prepared)?;
        let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
        let _authorized = kernel.authorize_create_founder_supporting_material()?;
        let request_metadata = frozen
            .request
            .client
            .as_ref()
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        let command_metadata = frozen
            .prepared
            .command
            .metadata
            .as_ref()
            .ok_or(ClientFounderSupportingMaterialError::InvalidInput)?;
        if session.authenticated_principal_id != frozen.prepared.authenticated_principal_id
            || session.session_id != frozen.prepared.session_id
            || request_metadata.session_id != frozen.prepared.session_id
            || request_metadata.correlation_id.as_deref()
                != Some(command_metadata.correlation_id.as_str())
            || frozen.request.command.as_ref() != Some(&frozen.prepared.command)
        {
            return Err(ClientFounderSupportingMaterialError::InvalidInput);
        }
        Ok(())
    })();
    if preflight.is_err() {
        return Err(ClientFounderSupportingMaterialError::Unknown {
            recovery: Box::new(frozen),
        });
    }
    dispatch_founder_supporting_material(frozen, send).await
}

async fn dispatch_founder_supporting_material<Send, SendFuture>(
    recovery: RecoverableFounderSupportingMaterial,
    send: Send,
) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
where
    Send: FnOnce(CreateFounderSupportingMaterialRequest) -> SendFuture,
    SendFuture: Future<Output = Result<CreateFounderSupportingMaterialResponse, String>>,
{
    let response = match send(recovery.request.clone()).await {
        Ok(response) => response,
        Err(_) => {
            return Err(ClientFounderSupportingMaterialError::Unknown {
                recovery: Box::new(recovery),
            });
        }
    };
    if response.gateway_error.is_some() || response.await_token.is_some() {
        return Err(ClientFounderSupportingMaterialError::Unknown {
            recovery: Box::new(recovery),
        });
    }
    let Some(receipt) = response.authority_result else {
        return Err(ClientFounderSupportingMaterialError::Unknown {
            recovery: Box::new(recovery),
        });
    };
    match ConfirmedFounderSupportingMaterialReceipt::from_prepared(receipt, &recovery.prepared) {
        Ok(confirmed) => Ok(confirmed),
        Err(_) => Err(ClientFounderSupportingMaterialError::Unknown {
            recovery: Box::new(recovery),
        }),
    }
}

fn canonical_founder_material_request_digest(
    command: &CreateFounderSupportingMaterialCommand,
) -> Option<String> {
    let mut canonical = command.clone();
    canonical.metadata.as_mut()?.request_digest_sha256.clear();
    Some(hex::encode(Sha256::digest(canonical.encode_to_vec())))
}

fn validate_founder_verdict_action(task_view: &TaskView) -> Result<(), &'static str> {
    let task = task_view.task.as_ref().ok_or("Task snapshot is missing")?;
    if task.status != DomainTaskStatus::VerdictPending as i32 {
        return Err("Task status is not VerdictPending");
    }
    if task.founder_verdict_id.is_some()
        || task_view.founder_verdict.is_some()
        || task_view.founder_verdict_state.is_some()
    {
        return Err("Task already has a Founder Verdict");
    }
    let mut verdict_actions = task_view
        .available_actions
        .iter()
        .filter(|action| action.kind == AvailableActionKind::SubmitFounderVerdict as i32);
    let verdict_action = verdict_actions
        .next()
        .ok_or("SubmitFounderVerdict is not available in the current projection")?;
    if verdict_actions.next().is_some()
        || verdict_action.owning_authority != "FounderVerdictAuthority"
        || verdict_action.derivation_rule_ref.trim().is_empty()
        || !verdict_action.explicit_confirmation_required
    {
        return Err("SubmitFounderVerdict action binding is invalid");
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ClientGuidedFounderVerdictError {
    #[error("Founder Verdict recovery could not be saved; no request was sent")]
    RecoveryStorage,
    #[error(
        "Founder Verdict Issue committed, but Apply recovery could not be saved; Apply was not sent"
    )]
    ApplyRecoveryStorage,
    #[error("client kernel rejected the guided Founder Verdict: {0}")]
    Kernel(#[from] KernelError),
    #[error("the current result review is invalid: {0}")]
    Review(#[from] ClientTaskResultReviewError),
    #[error("guided Founder Verdict input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("the current Task cannot accept a Founder Verdict: {0}")]
    NonActionable(&'static str),
    #[error("the result review is missing required real material: {0}")]
    MissingMaterial(&'static str),
    #[error(
        "Accept for {conclusion:?} requires complete risk coverage plus real rationale and compensating-control Artifacts"
    )]
    NonPassedAcceptRequiresRiskMaterials { conclusion: VerificationConclusion },
    #[error("Rework requires a real required-changes Artifact and a complete Rework directive")]
    ReworkRequiresDirectiveMaterials,
    #[error("the caller-supplied replay digest does not match the guided verdict payload")]
    RequestDigestMismatch,
    #[error("the sealed Founder Verdict no longer matches the current Task result review")]
    BindingChanged,
    #[error("authenticated Founder Verdict session changed before exact retry")]
    SessionChanged,
    #[error("Founder Verdict Authority rejected the guided verdict")]
    Authority {
        error_code: i32,
        safe_error_fingerprint: Option<String>,
    },
    #[error("Task Authority rejected the explicit Founder Verdict application")]
    TaskAuthority {
        error_code: i32,
        safe_detail_code: String,
    },
}

/// An Authority-confirmed Founder Verdict result. A missing await token means
/// the Authority commit is known but the local projection cannot yet be awaited.
#[derive(Clone, Debug, PartialEq)]
pub struct GuidedFounderVerdictResult {
    authority: VerdictCommandResult,
    await_token: Option<ProjectionAwaitToken>,
    projection_warning: Option<LocalApiError>,
}

impl GuidedFounderVerdictResult {
    #[must_use]
    pub fn committed(&self) -> bool {
        self.authority.committed
    }

    #[must_use]
    pub fn replayed(&self) -> bool {
        self.authority.replayed
    }

    #[must_use]
    pub fn founder_verdict_id(&self) -> &str {
        self.authority
            .verdict
            .as_ref()
            .expect("validated guided Founder Verdict result")
            .founder_verdict_id
            .as_str()
    }

    #[must_use]
    pub fn decision(&self) -> FounderVerdictDecision {
        FounderVerdictDecision::try_from(
            self.authority
                .verdict
                .as_ref()
                .expect("validated guided Founder Verdict result")
                .decision,
        )
        .expect("validated guided Founder Verdict decision")
    }

    #[must_use]
    pub fn await_token(&self) -> Option<&ProjectionAwaitToken> {
        self.await_token.as_ref()
    }

    #[must_use]
    pub fn projection_warning(&self) -> Option<&LocalApiError> {
        self.projection_warning.as_ref()
    }
}

/// The exact sealed command retained when the write outcome cannot be proven.
/// Its private fields prevent a retry from changing metadata, digest, expiry or
/// scope; retry only refreshes transport-level client request metadata.
#[derive(Clone, Debug)]
pub struct RecoverableGuidedFounderVerdict {
    authenticated_principal_id: String,
    session_id: String,
    selection: GuidedFounderVerdictSelection,
    command: VerdictCommand,
}

impl RecoverableGuidedFounderVerdict {
    #[must_use]
    pub fn sealed_command(&self) -> &VerdictCommand {
        &self.command
    }

    #[must_use]
    pub const fn selection(&self) -> GuidedFounderVerdictSelection {
        self.selection
    }
}

pub enum GuidedFounderVerdictAttempt {
    Committed(Box<GuidedFounderVerdictResult>),
    OutcomeUnknown(Box<RecoverableGuidedFounderVerdict>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuidedFounderDecisionStage {
    Issue,
    Apply,
}

/// A guided Founder decision is complete only when the issued Verdict has
/// been applied by Task Authority. The full validated Authority results remain
/// available to shared surfaces without exposing a second write path.
#[derive(Clone, Debug, PartialEq)]
pub struct GuidedFounderDecisionResult {
    verdict: GuidedFounderVerdictResult,
    task: TaskCommandResult,
    await_token: Option<ProjectionAwaitToken>,
    projection_warning: Option<LocalApiError>,
}

impl GuidedFounderDecisionResult {
    #[must_use]
    pub fn verdict(&self) -> &GuidedFounderVerdictResult {
        &self.verdict
    }

    #[must_use]
    pub fn task(&self) -> &TaskSnapshot {
        match self.task.outcome.as_ref() {
            Some(task_command_result::Outcome::Task(task)) => task,
            _ => unreachable!("validated guided Founder decision result"),
        }
    }

    #[must_use]
    pub fn task_replayed(&self) -> bool {
        self.task.replayed
    }

    #[must_use]
    pub fn await_token(&self) -> Option<&ProjectionAwaitToken> {
        self.await_token.as_ref()
    }

    #[must_use]
    pub fn projection_warning(&self) -> Option<&LocalApiError> {
        self.projection_warning.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProjectionPosition {
    pub epoch: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProjectionState {
    pub position: GovernedProjectionPosition,
    pub health: ProjectionHealth,
    pub stale: bool,
    pub reason: Option<GovernedProjectionReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedProjectionReason {
    DependencyProjectionPending,
    ProjectionNotReady,
    TaskProjectionInvalid,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedHoldReason {
    CancellationOutcomeUnknown,
    CompensationRequired,
    ManualRecoveryRequired,
    IrreversibleOutcomeUnknown,
    Unclassified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedAttemptState {
    pub attempt_id: String,
    pub revision: u64,
    pub attempt_number: u32,
    pub status: AttemptStatus,
    pub recovery_class: RecoveryClass,
    pub hold_reason: Option<GovernedHoldReason>,
    pub last_harness_sequence: u64,
    pub checkpoint_reference_recorded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedStepState {
    pub step_id: String,
    pub revision: u64,
    pub status: StepStatus,
    pub hold_reason: Option<GovernedHoldReason>,
    pub current_attempt_id: Option<String>,
    pub attempts: Vec<GovernedAttemptState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedRunState {
    pub run_id: String,
    pub revision: u64,
    pub status: RunStatus,
    pub work_revision: u64,
    pub hold_reason: Option<GovernedHoldReason>,
    pub steps: Vec<GovernedStepState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedTaskState {
    pub task_id: String,
    pub revision: u64,
    pub status: DomainTaskStatus,
    pub resume_status: Option<DomainTaskStatus>,
    pub hold_reason: Option<GovernedHoldReason>,
    pub projection: GovernedProjectionState,
    pub run: Option<GovernedRunState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedTaskUpdate {
    pub classification: TaskWatchClassification,
    pub position: GovernedProjectionPosition,
    pub task: Option<GovernedTaskState>,
}

#[derive(Debug, Error)]
pub enum ClientGovernedTaskError {
    #[error("client kernel rejected the governed Task read: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API governed Task transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the governed Task baseline: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("governed Task projection integrity failed: {0}")]
    Protocol(&'static str),
    #[error("governed Task baseline exceeded the 1000 item integrity limit")]
    BaselineLimitExceeded,
    #[error("governed Task watch ended unexpectedly")]
    UnexpectedEof,
    #[error("governed Task watch reached a reset barrier and requires baseline refetch")]
    ResetBarrier,
}

/// A complete governed Task snapshot. Its projection position is read-only,
/// internally non-replaceable and consumed with the snapshot when opening the
/// corresponding live session.
pub struct GovernedTaskBaseline {
    tasks: BTreeMap<String, GovernedTaskState>,
    position: GovernedProjectionPosition,
}

impl GovernedTaskBaseline {
    #[must_use]
    pub fn position(&self) -> &GovernedProjectionPosition {
        &self.position
    }

    #[must_use]
    pub fn tasks(&self) -> Vec<&GovernedTaskState> {
        self.tasks.values().collect()
    }
}

/// A governed Task baseline plus a live watch that starts at exactly that
/// baseline's internally bound projection position.
pub struct GovernedTaskSession {
    watch: TaskWatch,
    tasks: BTreeMap<String, GovernedTaskState>,
    last_position: GovernedProjectionPosition,
}

#[derive(Debug, Error)]
pub enum ClientTaskWatchError {
    #[error("client kernel rejected the Task watch: {0}")]
    Kernel(#[from] KernelError),
    #[error("Task watch resume epoch and sequence must be supplied together")]
    InvalidResumePair,
    #[error("local API Task watch transport failed: {0}")]
    Transport(String),
    #[error("Task watch reached a reset barrier and requires projection refetch")]
    ResetBarrier,
    #[error("Task watch ended after {received} frames before the requested {expected}")]
    PrematureEof { expected: u32, received: u32 },
}

impl From<ClientTaskWatchError> for ClientGovernedTaskError {
    fn from(value: ClientTaskWatchError) -> Self {
        match value {
            ClientTaskWatchError::Kernel(error) => Self::Kernel(error),
            ClientTaskWatchError::Transport(detail) => Self::Transport(detail),
            ClientTaskWatchError::ResetBarrier => Self::ResetBarrier,
            ClientTaskWatchError::InvalidResumePair => {
                Self::Protocol("governed Task baseline position is incomplete")
            }
            ClientTaskWatchError::PrematureEof { .. } => {
                Self::Protocol("governed Task watch frame bound is invalid")
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskWatchRequest {
    pub resume_epoch: Option<String>,
    pub resume_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskWatchClassification {
    Applied,
    Replay,
    Heartbeat,
    ResetRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskWatchFrameKind {
    Snapshot,
    Heartbeat,
    ResetRequired,
}

impl TaskWatchFrameKind {
    #[must_use]
    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::Snapshot => "STREAM_FRAME_KIND_SNAPSHOT",
            Self::Heartbeat => "STREAM_FRAME_KIND_HEARTBEAT",
            Self::ResetRequired => "STREAM_FRAME_KIND_RESET_REQUIRED",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskWatchUpdate {
    pub classification: TaskWatchClassification,
    pub kind: TaskWatchFrameKind,
    pub position: ProjectionPosition,
    pub view: Option<TaskView>,
    pub reset_reason_code: Option<String>,
}

#[derive(Default)]
struct TaskWatchProcessor {
    tracker: SnapshotStreamTracker,
    reset_barrier: bool,
}

impl TaskWatchProcessor {
    fn process(
        &mut self,
        frame: TaskViewStreamFrame,
    ) -> Result<TaskWatchUpdate, ClientTaskWatchError> {
        if self.reset_barrier {
            return Err(ClientTaskWatchError::ResetBarrier);
        }
        let frame_kind = StreamFrameKind::try_from(frame.kind)
            .map_err(|_| ClientTaskWatchError::Kernel(KernelError::UnknownStreamFrame))?;
        match frame_kind {
            StreamFrameKind::Snapshot | StreamFrameKind::Heartbeat
                if frame.reset_reason_code.is_some() =>
            {
                return Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            StreamFrameKind::ResetRequired
                if frame.reset_reason_code.as_deref().is_none_or(|reason| {
                    reason.is_empty()
                        || reason.len() > 128
                        || !reason.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'_' | b':' | b'-')
                        })
                }) =>
            {
                return Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            _ => {}
        }
        let applied = self.tracker.apply_task_frame(&frame)?;
        let kind = match frame_kind {
            StreamFrameKind::Snapshot => TaskWatchFrameKind::Snapshot,
            StreamFrameKind::Heartbeat => TaskWatchFrameKind::Heartbeat,
            StreamFrameKind::ResetRequired => TaskWatchFrameKind::ResetRequired,
            StreamFrameKind::Unspecified => {
                return Err(ClientTaskWatchError::Kernel(
                    KernelError::UnknownStreamFrame,
                ));
            }
        };
        let classification = match applied {
            StreamApply::Applied => TaskWatchClassification::Applied,
            StreamApply::Replay => TaskWatchClassification::Replay,
            StreamApply::Heartbeat => TaskWatchClassification::Heartbeat,
            StreamApply::ResetRequired => {
                self.reset_barrier = true;
                TaskWatchClassification::ResetRequired
            }
        };
        let position = frame.position.ok_or(ClientTaskWatchError::Kernel(
            KernelError::StreamPositionInvalid,
        ))?;
        Ok(TaskWatchUpdate {
            classification,
            kind,
            position,
            view: frame.snapshot,
            reset_reason_code: frame.reset_reason_code,
        })
    }
}

/// An attached Task projection watch. The tonic stream and stream tracker are
/// private to the shared operation so CLI/TUI surfaces cannot bypass replay or
/// reset-barrier validation.
pub struct TaskWatch {
    stream: tonic::Streaming<TaskViewStreamFrame>,
    processor: TaskWatchProcessor,
}

#[derive(Debug, Error)]
pub enum ClientApprovalWatchError {
    #[error("client kernel rejected the approval watch: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API approval watch transport failed: {0}")]
    Transport(String),
    #[error("local API approval watch ended unexpectedly")]
    UnexpectedEof,
    #[error("local API rejected the approval baseline: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("approval baseline exceeded the 1000 item integrity limit")]
    BaselineLimitExceeded,
    #[error("approval watch protocol integrity failed: {0}")]
    Protocol(&'static str),
    #[error("approval watch reached a reset barrier and requires baseline refetch")]
    ResetBarrier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalWatchCursor {
    pub epoch: String,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalWatchClassification {
    Applied,
    Replay,
    Heartbeat,
    ResetRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalWatchFrameKind {
    Snapshot,
    Heartbeat,
    ResetRequired,
}

impl ApprovalWatchFrameKind {
    #[must_use]
    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::Snapshot => "STREAM_FRAME_KIND_SNAPSHOT",
            Self::Heartbeat => "STREAM_FRAME_KIND_HEARTBEAT",
            Self::ResetRequired => "STREAM_FRAME_KIND_RESET_REQUIRED",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalWatchUpdate {
    pub classification: ApprovalWatchClassification,
    pub kind: ApprovalWatchFrameKind,
    pub position: ProjectionPosition,
    pub view: Option<HarnessApprovalView>,
    pub reset_reason_code: Option<String>,
}

/// One daemon-authored approval that is currently actionable. Construction is
/// private so presentation surfaces cannot forge the decision binding.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionableApproval {
    view: HarnessApprovalView,
}

impl ActionableApproval {
    #[must_use]
    pub fn view(&self) -> &HarnessApprovalView {
        &self.view
    }

    #[must_use]
    pub fn approval_request_id(&self) -> &str {
        &self.view.approval_request_id
    }

    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.view.task_id
    }

    #[must_use]
    pub fn action_digest_sha256(&self) -> &str {
        &self.view.action_digest_sha256
    }

    #[must_use]
    pub fn request_observation_id(&self) -> &str {
        &self.view.request_observation_id
    }

    #[must_use]
    pub const fn request_observation_sequence(&self) -> u64 {
        self.view.request_observation_sequence
    }

    #[must_use]
    pub const fn request_revision(&self) -> u64 {
        self.view.request_revision
    }
}

#[derive(Default)]
struct ApprovalWatchProcessor {
    tracker: SnapshotStreamTracker,
    reset_barrier: bool,
}

impl ApprovalWatchProcessor {
    fn process(
        &mut self,
        frame: HarnessApprovalViewStreamFrame,
    ) -> Result<ApprovalWatchUpdate, ClientApprovalWatchError> {
        if self.reset_barrier {
            return Err(ClientApprovalWatchError::ResetBarrier);
        }
        let frame_kind = StreamFrameKind::try_from(frame.kind)
            .map_err(|_| ClientApprovalWatchError::Kernel(KernelError::UnknownStreamFrame))?;
        match frame_kind {
            StreamFrameKind::Snapshot | StreamFrameKind::Heartbeat
                if frame.reset_reason_code.is_some() =>
            {
                return Err(ClientApprovalWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            StreamFrameKind::ResetRequired
                if frame.reset_reason_code.as_deref().is_none_or(|reason| {
                    reason.is_empty()
                        || reason.len() > 128
                        || !reason.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'_' | b':' | b'-')
                        })
                }) =>
            {
                return Err(ClientApprovalWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            _ => {}
        }
        let applied = self.tracker.apply_harness_approval_frame(&frame)?;
        let kind = match frame_kind {
            StreamFrameKind::Snapshot => ApprovalWatchFrameKind::Snapshot,
            StreamFrameKind::Heartbeat => ApprovalWatchFrameKind::Heartbeat,
            StreamFrameKind::ResetRequired => ApprovalWatchFrameKind::ResetRequired,
            StreamFrameKind::Unspecified => {
                return Err(ClientApprovalWatchError::Kernel(
                    KernelError::UnknownStreamFrame,
                ));
            }
        };
        let classification = match applied {
            StreamApply::Applied => ApprovalWatchClassification::Applied,
            StreamApply::Replay => ApprovalWatchClassification::Replay,
            StreamApply::Heartbeat => ApprovalWatchClassification::Heartbeat,
            StreamApply::ResetRequired => {
                self.reset_barrier = true;
                ApprovalWatchClassification::ResetRequired
            }
        };
        Ok(ApprovalWatchUpdate {
            classification,
            kind,
            position: frame.position.ok_or(ClientApprovalWatchError::Kernel(
                KernelError::StreamPositionInvalid,
            ))?,
            view: frame.snapshot,
            reset_reason_code: frame.reset_reason_code,
        })
    }
}

/// A stream-only approval watch. It classifies frames but never claims or
/// mutates a complete actionable queue.
pub struct ApprovalWatch {
    stream: tonic::Streaming<HarnessApprovalViewStreamFrame>,
    processor: ApprovalWatchProcessor,
}

/// A complete actionable queue snapshot. Its position and contents are
/// private and it is consumed when opening the corresponding live session.
pub struct ApprovalQueueBaseline {
    actionable: BTreeMap<String, ActionableApproval>,
    position: ProjectionPosition,
}

impl ApprovalQueueBaseline {
    #[must_use]
    pub fn position(&self) -> &ProjectionPosition {
        &self.position
    }

    #[must_use]
    pub fn actionable_approvals(&self) -> Vec<&ActionableApproval> {
        self.actionable.values().collect()
    }
}

/// A complete baseline plus updates that started at exactly that baseline's
/// private position.
pub struct ApprovalQueueSession {
    watch: ApprovalWatch,
    actionable: BTreeMap<String, ActionableApproval>,
    last_position: ProjectionPosition,
}

impl ApprovalWatch {
    pub async fn next_update(
        &mut self,
    ) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError> {
        let Self { stream, processor } = self;
        next_approval_watch_frame_via(processor, || async {
            stream.message().await.map_err(|error| error.to_string())
        })
        .await
    }
}

impl ApprovalQueueSession {
    #[must_use]
    pub(crate) fn position(&self) -> &ProjectionPosition {
        &self.last_position
    }

    #[must_use]
    pub fn actionable_approvals(&self) -> Vec<&ActionableApproval> {
        self.actionable.values().collect()
    }

    pub async fn next_update(
        &mut self,
    ) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError> {
        let update = self.watch.next_update().await?;
        if let Some(update) = &update
            && let Err(error) = apply_approval_queue_session_update(
                &mut self.actionable,
                &mut self.last_position,
                update,
            )
        {
            self.watch.processor.reset_barrier = true;
            return Err(error);
        }
        Ok(update)
    }
}

fn apply_approval_queue_session_update(
    actionable: &mut BTreeMap<String, ActionableApproval>,
    last_position: &mut ProjectionPosition,
    update: &ApprovalWatchUpdate,
) -> Result<(), ClientApprovalWatchError> {
    if update.classification != ApprovalWatchClassification::ResetRequired
        && update.position.epoch != last_position.epoch
    {
        return Err(ClientApprovalWatchError::Kernel(
            KernelError::StreamResetMissing,
        ));
    }
    if update.classification == ApprovalWatchClassification::ResetRequired {
        return Ok(());
    }
    if update.position.sequence < last_position.sequence {
        return Err(ClientApprovalWatchError::Kernel(
            KernelError::StreamOutOfOrder,
        ));
    }
    if update.position.sequence == last_position.sequence {
        return match update.classification {
            ApprovalWatchClassification::Applied => apply_approval_watch_update(actionable, update),
            ApprovalWatchClassification::Replay | ApprovalWatchClassification::Heartbeat => Ok(()),
            ApprovalWatchClassification::ResetRequired => unreachable!("handled above"),
        };
    }
    apply_approval_watch_update(actionable, update)?;
    *last_position = update.position.clone();
    Ok(())
}

async fn next_approval_watch_frame_via<F, Fut>(
    processor: &mut ApprovalWatchProcessor,
    next_message: F,
) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<HarnessApprovalViewStreamFrame>, String>>,
{
    if processor.reset_barrier {
        return Err(ClientApprovalWatchError::ResetBarrier);
    }
    let Some(frame) = next_message()
        .await
        .map_err(ClientApprovalWatchError::Transport)?
    else {
        return Err(ClientApprovalWatchError::UnexpectedEof);
    };
    processor.process(frame).map(Some)
}

#[cfg(test)]
async fn next_approval_queue_update_via<F, Fut>(
    processor: &mut ApprovalWatchProcessor,
    actionable: &mut BTreeMap<String, ActionableApproval>,
    next_message: F,
) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<HarnessApprovalViewStreamFrame>, String>>,
{
    let update = next_approval_watch_frame_via(processor, next_message).await?;
    if let Some(update) = &update {
        apply_approval_watch_update(actionable, update)?;
    }
    Ok(update)
}

fn is_actionable_approval(view: &HarnessApprovalView) -> Result<bool, ClientApprovalWatchError> {
    let mut actionable = false;
    for action in &view.available_actions {
        let kind = AvailableActionKind::try_from(action.kind)
            .map_err(|_| ClientApprovalWatchError::Protocol("approval action kind is unknown"))?;
        if kind == AvailableActionKind::Unspecified {
            return Err(ClientApprovalWatchError::Protocol(
                "approval action kind is unspecified",
            ));
        }
        actionable |= kind == AvailableActionKind::DecideHarnessApproval;
    }
    Ok(actionable)
}

fn apply_approval_watch_update(
    actionable: &mut BTreeMap<String, ActionableApproval>,
    update: &ApprovalWatchUpdate,
) -> Result<(), ClientApprovalWatchError> {
    if update.classification != ApprovalWatchClassification::Applied {
        return Ok(());
    }
    let view = update
        .view
        .as_ref()
        .ok_or(ClientApprovalWatchError::Protocol(
            "applied approval frame missing view",
        ))?;
    if view.approval_request_id.is_empty() {
        return Err(ClientApprovalWatchError::Protocol(
            "approval request id missing",
        ));
    }
    if is_actionable_approval(view)? {
        actionable.insert(
            view.approval_request_id.clone(),
            ActionableApproval { view: view.clone() },
        );
    } else {
        actionable.remove(&view.approval_request_id);
    }
    Ok(())
}

impl TaskWatch {
    pub async fn next_update(&mut self) -> Result<Option<TaskWatchUpdate>, ClientTaskWatchError> {
        let Self { stream, processor } = self;
        next_task_watch_update_via(processor, || async {
            stream.message().await.map_err(|error| error.to_string())
        })
        .await
    }
}

impl GovernedTaskSession {
    #[must_use]
    pub fn tasks(&self) -> Vec<&GovernedTaskState> {
        self.tasks.values().collect()
    }

    #[must_use]
    pub fn position(&self) -> &GovernedProjectionPosition {
        &self.last_position
    }

    pub async fn next_update(&mut self) -> Result<GovernedTaskUpdate, ClientGovernedTaskError> {
        let TaskWatch { stream, processor } = &mut self.watch;
        next_governed_task_session_update_via(
            processor,
            &mut self.tasks,
            &mut self.last_position,
            || async { stream.message().await.map_err(|error| error.to_string()) },
        )
        .await
    }
}

async fn next_governed_task_session_update_via<F, Fut>(
    processor: &mut TaskWatchProcessor,
    tasks: &mut BTreeMap<String, GovernedTaskState>,
    last_position: &mut GovernedProjectionPosition,
    next_message: F,
) -> Result<GovernedTaskUpdate, ClientGovernedTaskError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<TaskViewStreamFrame>, String>>,
{
    let raw = next_task_watch_update_via(processor, next_message)
        .await
        .map_err(ClientGovernedTaskError::from)?
        .ok_or(ClientGovernedTaskError::UnexpectedEof)?;
    let update = match governed_task_update_from_watch(raw) {
        Ok(update) => update,
        Err(error) => {
            processor.reset_barrier = true;
            return Err(error);
        }
    };
    if let Err(error) = apply_governed_task_session_update(tasks, last_position, &update) {
        processor.reset_barrier = true;
        return Err(error);
    }
    Ok(update)
}

async fn next_task_watch_update_via<F, Fut>(
    processor: &mut TaskWatchProcessor,
    next_message: F,
) -> Result<Option<TaskWatchUpdate>, ClientTaskWatchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<TaskViewStreamFrame>, String>>,
{
    if processor.reset_barrier {
        return Err(ClientTaskWatchError::ResetBarrier);
    }
    let Some(frame) = next_message()
        .await
        .map_err(ClientTaskWatchError::Transport)?
    else {
        return Ok(None);
    };
    processor.process(frame).map(Some)
}

#[derive(Debug, Error)]
pub enum ClientWorkError {
    #[error("client kernel rejected the work operation: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the work operation: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("local API returned an incomplete work response: {0}")]
    Protocol(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedWorkCapabilityAvailability {
    Admitted,
    Candidate,
    Held,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedWorkCapabilitySelectionSource {
    FutureWorkDefault,
    ExplicitChoice,
    LegacyOmittedDefault,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedWorkCapability {
    pub provider_profile_id: String,
    pub provider_alias: String,
    pub harness_alias: String,
    pub harness_model_alias: String,
    pub provider_model_alias: String,
    pub availability: GovernedWorkCapabilityAvailability,
    pub selectable: bool,
    pub safe_reason_code: Option<String>,
    pub choice_id: Option<String>,
    pub route_binding_sha256: Option<String>,
    pub current_future_work_default: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedWorkCapabilityCatalog {
    pub capabilities: Vec<GovernedWorkCapability>,
    pub default_choice_id: String,
    pub preference_revision: u64,
    pub configuration_migration_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuidedWorkSource {
    pub source_ref: String,
    pub label: String,
}

/// Per-work Memory consent. Surfaces choose one of these two user-visible
/// modes; they cannot choose an algorithm, snapshot, record or Authority
/// revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuidedWorkMemoryMode {
    Disabled,
    GovernedRetrieval,
}

/// Closed user choice for one work item. The public identifier is resolved by
/// the daemon; clients cannot supply an authoritative route tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuidedWorkCapabilityChoice {
    FutureWorkDefault,
    Explicit(String),
}

impl GuidedWorkCapabilityChoice {
    fn to_wire(&self) -> prepare_work_request::WorkCapabilityPreference {
        match self {
            Self::FutureWorkDefault => {
                prepare_work_request::WorkCapabilityPreference::UseDefaultWorkCapability(
                    UseDefaultWorkCapability {},
                )
            }
            Self::Explicit(choice_id) => {
                prepare_work_request::WorkCapabilityPreference::ExplicitWorkCapabilityChoiceId(
                    choice_id.clone(),
                )
            }
        }
    }
}

impl GuidedWorkMemoryMode {
    const fn wire_value(self) -> i32 {
        match self {
            Self::Disabled => WorkMemoryMode::Disabled as i32,
            Self::GovernedRetrieval => WorkMemoryMode::GovernedRetrieval as i32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuidedWorkInput {
    pub intent: String,
    pub work_type: String,
    pub target_scope_ref: String,
    pub sources: Vec<GuidedWorkSource>,
    pub memory_mode: GuidedWorkMemoryMode,
    pub capability: GuidedWorkCapabilityChoice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuidedWorkNonGoal {
    ProviderRouteCannotBeModelSelected,
    MemoryMutationExcluded,
}

impl GuidedWorkNonGoal {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProviderRouteCannotBeModelSelected => {
                "provider/model route cannot be selected or changed by model output"
            }
            Self::MemoryMutationExcluded => "memory is not mutated by preparation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedWorkNotice {
    ContextSourceEmpty,
    ContextSourceOutsideWorkspace,
    ContextSourceUnreadable,
    ContextSourceTooLarge,
    MemoryRetrievalEmpty,
    MemoryContentBudgetExcluded,
}

impl GovernedWorkNotice {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ContextSourceEmpty => "CONTEXT_SOURCE_EMPTY",
            Self::ContextSourceOutsideWorkspace => "CONTEXT_SOURCE_OUTSIDE_WORKSPACE",
            Self::ContextSourceUnreadable => "CONTEXT_SOURCE_UNREADABLE",
            Self::ContextSourceTooLarge => "CONTEXT_SOURCE_TOO_LARGE",
            Self::MemoryRetrievalEmpty => "MEMORY_RETRIEVAL_EMPTY",
            Self::MemoryContentBudgetExcluded => "MEMORY_CONTENT_BUDGET_EXCLUDED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuidedWorkPreview {
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

impl GuidedWorkPreview {
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

/// A daemon-produced work preview sealed to the authenticated session and to
/// the exact confirmation command. It is deliberately non-cloneable and has
/// no public constructor or mutation surface.
pub struct PreparedWork {
    authenticated_principal_id: String,
    session_id: String,
    preview: WorkPreparationPreview,
    safe_preview: GuidedWorkPreview,
    prepare_idempotency_key: String,
    confirm_idempotency_key: String,
}

impl PreparedWork {
    #[must_use]
    pub fn preview(&self) -> &GuidedWorkPreview {
        &self.safe_preview
    }
}

/// The exact already-sealed confirmation command retained after an uncertain
/// transport outcome. Replaying this value never prepares again or changes
/// the idempotency key.
pub struct RecoverableWorkConfirmation {
    authenticated_principal_id: String,
    session_id: String,
    request: ConfirmWorkRequest,
    expected_snapshot_id: String,
    expected_confirmation_binding_sha256: String,
    expected_work_type: String,
    expected_target_scope_ref: String,
}

pub struct RecoverableWorkPreparation {
    authenticated_principal_id: String,
    session_id: String,
    request: PrepareWorkRequest,
    confirm_idempotency_key: String,
}

pub enum GuidedWorkPreparationAttempt {
    Prepared(Box<PreparedWork>),
    OutcomeUnknown(Box<RecoverableWorkPreparation>),
}

#[cfg(test)]
impl GuidedWorkPreparationAttempt {
    fn expect_prepared(self) -> PreparedWork {
        match self {
            Self::Prepared(prepared) => *prepared,
            Self::OutcomeUnknown(_) => panic!("expected prepared work"),
        }
    }
}

#[derive(Debug, Error)]
pub enum ClientGuidedWorkError {
    #[error("client kernel rejected the guided work operation: {0}")]
    Kernel(#[from] KernelError),
    #[error("guided work input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("the prepared work is blocked and cannot be confirmed")]
    Blocked,
    #[error("authenticated work session changed after preparation")]
    SessionChanged,
    #[error("the prepared work binding changed before confirmation")]
    BindingChanged,
    #[error("guided work preparation outcome is unknown: {0}")]
    PreparationOutcomeUnknown(String),
    #[error("guided work confirmation outcome is unknown: {0}")]
    ConfirmationOutcomeUnknown(String),
    #[error("guided work returned an API error without proving the commit outcome")]
    ApiOutcomeUnknown(Box<LocalApiError>),
    #[error("local API rejected the guided work operation: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("Task Authority rejected the guided work confirmation")]
    Authority {
        error_code: i32,
        safe_detail_code: String,
    },
    #[error("local API returned an incomplete guided work response: {0}")]
    Protocol(&'static str),
}

pub enum GuidedWorkConfirmationAttempt {
    Confirmed(Box<ConfirmedWork>),
    OutcomeUnknown(Box<RecoverableWorkConfirmation>),
}

#[derive(Debug, Error)]
pub enum ClientContextRevokeError {
    #[error("client kernel rejected the Context revoke: {0}")]
    Kernel(#[from] KernelError),
    #[error("Context revoke confirmation digest is invalid")]
    InvalidConfirmation,
    #[error("authenticated Context revoke session changed after preparation")]
    SessionChanged,
    #[error("local API transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the Context revoke: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("local API returned a malformed Context revoke response: {0}")]
    MalformedResponse(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConfirmedWork {
    pub result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
    pub await_token:
        Option<egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionAwaitToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRevokeInput {
    pub snapshot_id: String,
    pub expected_state_revision: u64,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
    pub confirmation_proof_ref: String,
    pub idempotency_key: String,
}

/// A semantic Context revoke bound to the exact authenticated session that
/// prepared it. Sensitive confirmation material remains private so surfaces
/// can display only the frozen digest and safe routing facts.
pub struct PreparedContextRevoke {
    authenticated_principal_id: String,
    session_id: String,
    snapshot_id: String,
    expected_state_revision: u64,
    reason_code: String,
    evidence_refs: Vec<String>,
    confirmation_proof_ref: String,
    idempotency_key: String,
    request_digest_sha256: String,
}

impl PreparedContextRevoke {
    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn expected_state_revision(&self) -> u64 {
        self.expected_state_revision
    }

    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_refs.len()
    }

    #[must_use]
    pub fn request_digest_sha256(&self) -> &str {
        &self.request_digest_sha256
    }
}

impl ClientAttachment {
    pub fn metadata(
        &self,
        correlation_id: Option<String>,
    ) -> Result<ClientRequestMetadata, KernelError> {
        self.kernel.request_metadata(
            Uuid::now_v7().to_string(),
            correlation_id,
            SystemTime::now(),
        )
    }

    pub fn require_rpc(&self, rpc: &str) -> Result<(), KernelError> {
        let session = self
            .kernel
            .session()
            .ok_or(KernelError::SessionUnavailable)?;
        self.kernel
            .profiles()
            .authorize_rpc(rpc, &session.granted_permission_codes)
            .map(|_| ())
    }

    pub fn require_command(&self, rpc: &str, oneof: &str) -> Result<(), KernelError> {
        let session = self
            .kernel
            .session()
            .ok_or(KernelError::SessionUnavailable)?;
        self.kernel
            .profiles()
            .authorize_command(rpc, oneof, &session.granted_permission_codes)
            .map(|_| ())
    }

    pub async fn read_governed_task_baseline(
        &self,
    ) -> Result<GovernedTaskBaseline, ClientGovernedTaskError> {
        let client = self.connection.read_model_service();
        read_governed_task_baseline_via(&self.kernel, SystemTime::now(), move |request| {
            let mut client = client.clone();
            async move {
                client
                    .list_task_views(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            }
        })
        .await
    }

    pub async fn open_governed_task_session(
        &self,
        baseline: GovernedTaskBaseline,
    ) -> Result<GovernedTaskSession, ClientGovernedTaskError> {
        let GovernedTaskBaseline { tasks, position } = baseline;
        let watch = self
            .open_task_watch(TaskWatchRequest {
                resume_epoch: Some(position.epoch.clone()),
                resume_sequence: Some(position.sequence),
            })
            .await
            .map_err(ClientGovernedTaskError::from)?;
        Ok(GovernedTaskSession {
            watch,
            tasks,
            last_position: position,
        })
    }

    pub async fn open_task_watch(
        &self,
        request: TaskWatchRequest,
    ) -> Result<TaskWatch, ClientTaskWatchError> {
        let mut client = self.connection.read_model_service();
        let stream = open_task_watch_via(
            &self.kernel,
            request,
            SystemTime::now(),
            move |wire_request| async move {
                client
                    .watch_task_views(wire_request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await?;
        Ok(TaskWatch {
            stream,
            processor: TaskWatchProcessor::default(),
        })
    }

    pub async fn read_actionable_approval_queue(
        &self,
    ) -> Result<ApprovalQueueBaseline, ClientApprovalWatchError> {
        let client = self.connection.read_model_service();
        read_actionable_approval_queue_via(&self.kernel, SystemTime::now(), move |request| {
            let mut client = client.clone();
            async move {
                client
                    .list_harness_approval_views(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            }
        })
        .await
    }

    pub async fn decide_guided_approval(
        &self,
        input: GuidedApprovalDecisionInput,
    ) -> Result<GuidedApprovalDecisionResult, ClientGuidedApprovalDecisionError> {
        let mut read_client = self.connection.read_model_service();
        let mut command_client = self.connection.command_gateway_service();
        decide_guided_approval_via(
            &self.kernel,
            input,
            SystemTime::now(),
            move |request| async move {
                read_client
                    .get_harness_approval_view(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
            move |request| async move {
                command_client
                    .decide_harness_approval(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub async fn open_approval_queue_from(
        &self,
        baseline: ApprovalQueueBaseline,
    ) -> Result<ApprovalQueueSession, ClientApprovalWatchError> {
        let ApprovalQueueBaseline {
            actionable,
            position,
        } = baseline;
        let watch = self.open_approval_stream(Some(position.clone())).await?;
        Ok(ApprovalQueueSession {
            watch,
            actionable,
            last_position: position,
        })
    }

    pub async fn open_approval_watch_resume(
        &self,
        cursor: ApprovalWatchCursor,
    ) -> Result<ApprovalWatch, ClientApprovalWatchError> {
        if cursor.epoch.is_empty() {
            return Err(ClientApprovalWatchError::Protocol(
                "approval watch resume epoch missing",
            ));
        }
        self.open_approval_stream(Some(ProjectionPosition {
            epoch: cursor.epoch,
            sequence: cursor.sequence,
            projected_at: None,
        }))
        .await
    }

    pub async fn open_approval_watch_current(
        &self,
    ) -> Result<ApprovalWatch, ClientApprovalWatchError> {
        self.open_approval_stream(None).await
    }

    async fn open_approval_stream(
        &self,
        resume_after: Option<ProjectionPosition>,
    ) -> Result<ApprovalWatch, ClientApprovalWatchError> {
        let mut client = self.connection.read_model_service();
        let stream = open_approval_stream_via(
            &self.kernel,
            resume_after,
            SystemTime::now(),
            move |request| async move {
                client
                    .watch_harness_approval_views(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await?;
        Ok(ApprovalWatch {
            stream,
            processor: ApprovalWatchProcessor::default(),
        })
    }

    /// Prepares the single confirmation digest shared by CLI and TUI without
    /// sending a request. The authenticated Founder identity comes only from
    /// the accepted local session and is frozen into the semantic digest.
    pub fn prepare_context_revoke(
        &self,
        input: ContextRevokeInput,
    ) -> Result<PreparedContextRevoke, ClientContextRevokeError> {
        prepare_context_revoke_with_kernel(&self.kernel, input)
    }

    /// Executes exactly the prepared Context revoke after checking that the
    /// same authenticated session supplied the exact displayed digest.
    pub async fn execute_context_revoke(
        &self,
        prepared: PreparedContextRevoke,
        supplied_digest_sha256: &str,
    ) -> Result<ContextRevokeReceipt, ClientContextRevokeError> {
        let mut client = self.connection.command_gateway_service();
        execute_context_revoke_via(
            &self.kernel,
            prepared,
            supplied_digest_sha256,
            SystemTime::now(),
            move |request| async move {
                client
                    .execute_context_mutation(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub async fn read_projection_snapshot(&self) -> Result<ProjectionSnapshot, ClientReadError> {
        let status = self
            .connection
            .read_model_service()
            .get_projection_status(GetProjectionStatusRequest {
                client: Some(self.metadata(None)?),
            })
            .await
            .map_err(|error| ClientReadError::Transport(error.to_string()))?
            .into_inner();
        if let Some(error) = status.error {
            return Err(ClientReadError::Api(Box::new(error)));
        }
        let metadata = status
            .metadata
            .ok_or(ClientReadError::Protocol("projection metadata missing"))?;

        let tasks = self
            .connection
            .read_model_service()
            .list_task_views(ListTaskViewsRequest {
                client: Some(self.metadata(None)?),
                status_filter: Vec::new(),
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| ClientReadError::Transport(error.to_string()))?
            .into_inner();
        if let Some(error) = tasks.error {
            return Err(ClientReadError::Api(Box::new(error)));
        }

        let approvals = self
            .connection
            .read_model_service()
            .list_harness_approval_views(ListHarnessApprovalViewsRequest {
                client: Some(self.metadata(None)?),
                request_lifecycle_filter: Vec::new(),
                decision_state_filter: Vec::new(),
                task_ids: Vec::new(),
                actionable_only: false,
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| ClientReadError::Transport(error.to_string()))?
            .into_inner();
        if let Some(error) = approvals.error {
            return Err(ClientReadError::Api(Box::new(error)));
        }

        Ok(ProjectionSnapshot {
            metadata,
            tasks: tasks.views,
            approvals: approvals.views,
        })
    }

    /// Reads projected result metadata and its governance evidence without
    /// accepting an ArtifactSet identity from the caller.
    pub async fn read_task_result_review(
        &self,
        task_id: &str,
    ) -> Result<TaskResultReview, ClientTaskResultReviewError> {
        let read_client = self.connection.read_model_service();
        let evidence_client = read_client.clone();
        read_task_result_review_via(
            &self.kernel,
            task_id,
            SystemTime::now(),
            move |request| {
                let mut client = read_client;
                async move {
                    client
                        .get_task_view(request)
                        .await
                        .map(|response| response.into_inner())
                        .map_err(|error| error.to_string())
                }
            },
            move |request| {
                let mut client = evidence_client;
                async move {
                    client
                        .get_evidence_graph(request)
                        .await
                        .map(|response| response.into_inner())
                        .map_err(|error| error.to_string())
                }
            },
        )
        .await
    }

    /// Validates the exact sealed command against the current result review,
    /// then submits it through the existing Founder Verdict gateway.
    pub async fn submit_guided_founder_verdict(
        &self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
    ) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError> {
        self.submit_guided_founder_verdict_inner(command, selection, None, None)
            .await
    }

    pub async fn submit_guided_founder_verdict_with_materials(
        &self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
        materials: &FounderSupportingMaterialCollection,
    ) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError> {
        self.submit_guided_founder_verdict_inner(command, selection, Some(materials), None)
            .await
    }

    async fn submit_guided_founder_verdict_inner(
        &self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
        materials: Option<&FounderSupportingMaterialCollection>,
        recovery_path: Option<&std::path::Path>,
    ) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError> {
        let read_client = self.connection.read_model_service();
        let evidence_client = read_client.clone();
        let mut command_client = self.connection.command_gateway_service();
        submit_guided_founder_verdict_materials_via(
            &self.kernel,
            GuidedFounderVerdictSubmission {
                command,
                selection,
                materials,
                recovery_path,
            },
            SystemTime::now(),
            move |request| {
                let mut client = read_client;
                async move {
                    client
                        .get_task_view(request)
                        .await
                        .map(|response| response.into_inner())
                        .map_err(|error| error.to_string())
                }
            },
            move |request| {
                let mut client = evidence_client;
                async move {
                    client
                        .get_evidence_graph(request)
                        .await
                        .map(|response| response.into_inner())
                        .map_err(|error| error.to_string())
                }
            },
            move |request| async move {
                command_client
                    .execute_founder_verdict(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    /// Sends one frozen supporting-material command. The command payload is
    /// retained verbatim by callers for an exact retry when delivery is
    /// unknown; this method never rebuilds it from display text or an artifact
    /// identifier.
    pub async fn create_founder_supporting_material(
        &self,
        prepared: PreparedFounderSupportingMaterial,
    ) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
    {
        let mut client = self.connection.command_gateway_service();
        submit_founder_supporting_material_via(
            &self.kernel,
            prepared,
            SystemTime::now(),
            move |request| async move {
                client
                    .create_founder_supporting_material(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub async fn retry_founder_supporting_material(
        &self,
        recovery: &RecoverableFounderSupportingMaterial,
    ) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
    {
        let mut client = self.connection.command_gateway_service();
        retry_founder_supporting_material_via(&self.kernel, recovery, move |request| async move {
            client
                .create_founder_supporting_material(request)
                .await
                .map(|response| response.into_inner())
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// Retries only the exact command retained after an unknown write outcome.
    /// It intentionally does not read a newer result review or rebuild scope.
    pub async fn retry_guided_founder_verdict(
        &self,
        recovery: &RecoverableGuidedFounderVerdict,
    ) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError> {
        let mut command_client = self.connection.command_gateway_service();
        retry_guided_founder_verdict_via(
            &self.kernel,
            recovery,
            SystemTime::now(),
            move |request| async move {
                command_client
                    .execute_founder_verdict(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    /// Prepares a guided work start from user-owned intent only. Both
    /// idempotency keys are generated once here and remain private.
    pub async fn prepare_guided_work(
        &self,
        input: GuidedWorkInput,
    ) -> Result<GuidedWorkPreparationAttempt, ClientGuidedWorkError> {
        let mut client = self.connection.command_gateway_service();
        prepare_guided_work_via(
            &self.kernel,
            input,
            SystemTime::now(),
            move |request| async move {
                client
                    .prepare_work(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub async fn replay_guided_work_preparation(
        &self,
        recovery: &RecoverableWorkPreparation,
    ) -> Result<PreparedWork, ClientGuidedWorkError> {
        let mut client = self.connection.command_gateway_service();
        replay_guided_work_preparation_via(&self.kernel, recovery, move |request| async move {
            client
                .prepare_work(request)
                .await
                .map(|response| response.into_inner())
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// Consumes one prepared preview and sends its exact sealed confirmation
    /// command once. A transport failure returns the sealed command so the
    /// caller can explicitly replay it without preparing again.
    pub async fn confirm_guided_work(
        &self,
        prepared: PreparedWork,
    ) -> Result<GuidedWorkConfirmationAttempt, ClientGuidedWorkError> {
        let mut client = self.connection.command_gateway_service();
        confirm_guided_work_via(
            &self.kernel,
            prepared,
            SystemTime::now(),
            move |request| async move {
                client
                    .confirm_work(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    /// Replays the exact previously sealed confirmation request. The recovery
    /// value is borrowed, so another uncertain transport outcome cannot erase
    /// the only replayable command.
    pub async fn replay_guided_work_confirmation(
        &self,
        recovery: &RecoverableWorkConfirmation,
    ) -> Result<ConfirmedWork, ClientGuidedWorkError> {
        let mut client = self.connection.command_gateway_service();
        replay_guided_work_confirmation_via(&self.kernel, recovery, move |request| async move {
            client
                .confirm_work(request)
                .await
                .map(|response| response.into_inner())
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// Lists redaction-safe route choices through the same shared kernel used
    /// by every surface. Candidate and held entries remain visible but cannot
    /// carry a selectable choice or admitted route.
    pub async fn list_work_capabilities(
        &self,
    ) -> Result<GovernedWorkCapabilityCatalog, ClientWorkError> {
        self.require_rpc(LIST_WORK_CAPABILITIES_RPC)?;
        let response = self
            .connection
            .command_gateway_service()
            .list_work_capabilities(ListWorkCapabilitiesRequest {
                client: Some(self.metadata(None)?),
            })
            .await
            .map_err(|error| ClientWorkError::Transport(error.to_string()))?
            .into_inner();
        match response.outcome {
            Some(list_work_capabilities_response::Outcome::Result(result)) => {
                parse_work_capability_catalog(result)
            }
            Some(list_work_capabilities_response::Outcome::Error(error)) => {
                Err(ClientWorkError::Api(Box::new(error)))
            }
            None => Err(ClientWorkError::Protocol(
                "work capability list outcome missing",
            )),
        }
    }

    pub async fn set_default_work_capability(
        &self,
        choice_id: String,
        expected_preference_revision: u64,
    ) -> Result<WorkCapabilityPreferenceReceipt, ClientWorkError> {
        self.require_rpc(SET_DEFAULT_WORK_CAPABILITY_RPC)?;
        if !is_guided_work_text(&choice_id, GUIDED_WORK_MAX_ROUTING_BYTES)
            || expected_preference_revision == 0
        {
            return Err(ClientWorkError::Protocol(
                "work capability preference input is invalid",
            ));
        }
        let response = self
            .connection
            .command_gateway_service()
            .set_default_work_capability(SetDefaultWorkCapabilityRequest {
                client: Some(self.metadata(None)?),
                choice_id: choice_id.clone(),
                expected_preference_revision,
            })
            .await
            .map_err(|error| ClientWorkError::Transport(error.to_string()))?
            .into_inner();
        match response.outcome {
            Some(set_default_work_capability_response::Outcome::Receipt(receipt))
                if receipt.default_choice_id == choice_id
                    && receipt.previous_preference_revision == expected_preference_revision
                    && ((!receipt.changed
                        && receipt.preference_revision == expected_preference_revision)
                        || (receipt.changed
                            && receipt.preference_revision
                                == expected_preference_revision.saturating_add(1))) =>
            {
                Ok(receipt)
            }
            Some(set_default_work_capability_response::Outcome::Receipt(_)) => Err(
                ClientWorkError::Protocol("work capability preference receipt is invalid"),
            ),
            Some(set_default_work_capability_response::Outcome::Error(error)) => {
                Err(ClientWorkError::Api(Box::new(error)))
            }
            None => Err(ClientWorkError::Protocol(
                "work capability preference outcome missing",
            )),
        }
    }

    /// The shared client operation for both CLI and TUI. The request contains
    /// only user intent, scope and explicit source references; all governance
    /// facts are returned by the daemon-owned preparation compiler.
    pub async fn prepare_work(
        &self,
        input: GuidedWorkInput,
        idempotency_key: String,
    ) -> Result<WorkPreparationPreview, ClientWorkError> {
        let GuidedWorkInput {
            intent,
            work_type,
            target_scope_ref,
            sources,
            memory_mode,
            capability,
        } = input;
        let response = self
            .connection
            .command_gateway_service()
            .prepare_work(PrepareWorkRequest {
                client: Some(self.metadata(None)?),
                intent,
                work_type,
                target_scope_ref,
                sources: sources
                    .into_iter()
                    .map(|source| WorkSourceRequest {
                        source_ref: source.source_ref,
                        label: source.label,
                    })
                    .collect(),
                idempotency_key,
                memory_mode: memory_mode.wire_value(),
                work_capability_preference: Some(capability.to_wire()),
            })
            .await
            .map_err(|error| ClientWorkError::Transport(error.to_string()))?
            .into_inner();
        match response.outcome {
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Preview(preview)) => Ok(preview),
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Error(error)) => Err(ClientWorkError::Api(Box::new(error))),
            None => Err(ClientWorkError::Protocol("prepare outcome missing")),
        }
    }

    /// Confirms exactly the binding displayed in the preparation preview. The
    /// daemon—not this client—creates the Task command through Task Authority.
    pub async fn confirm_work(
        &self,
        snapshot_id: String,
        confirmation_binding_sha256: String,
        idempotency_key: String,
    ) -> Result<ConfirmedWork, ClientWorkError> {
        let response: ConfirmWorkResponse = self
            .connection
            .command_gateway_service()
            .confirm_work(ConfirmWorkRequest {
                client: Some(self.metadata(None)?),
                snapshot_id,
                confirmation_binding_sha256,
                idempotency_key,
            })
            .await
            .map_err(|error| ClientWorkError::Transport(error.to_string()))?
            .into_inner();
        match response.outcome {
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Accepted(accepted)) => Ok(ConfirmedWork {
                result: accepted.authority_result.ok_or(ClientWorkError::Protocol("confirmed task result missing"))?,
                await_token: accepted.await_token,
            }),
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Error(error)) => Err(ClientWorkError::Api(Box::new(error))),
            None => Err(ClientWorkError::Protocol("confirm outcome missing")),
        }
    }
}

async fn prepare_guided_work_via<F, Fut>(
    kernel: &ClientKernel,
    input: GuidedWorkInput,
    now: SystemTime,
    send: F,
) -> Result<GuidedWorkPreparationAttempt, ClientGuidedWorkError>
where
    F: FnOnce(PrepareWorkRequest) -> Fut,
    Fut: Future<Output = Result<PrepareWorkResponse, String>>,
{
    validate_guided_work_input(&input)?;
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(PREPARE_WORK_RPC, &session.granted_permission_codes)?;
    kernel
        .profiles()
        .authorize_rpc(CONFIRM_WORK_RPC, &session.granted_permission_codes)?;
    let client = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    let prepare_idempotency_key = format!("guided-work-prepare:{}", Uuid::now_v7());
    let request = PrepareWorkRequest {
        client: Some(client),
        intent: input.intent,
        work_type: input.work_type.clone(),
        target_scope_ref: input.target_scope_ref.clone(),
        sources: input
            .sources
            .into_iter()
            .map(|source| WorkSourceRequest {
                source_ref: source.source_ref,
                label: source.label,
            })
            .collect(),
        idempotency_key: prepare_idempotency_key,
        memory_mode: input.memory_mode.wire_value(),
        work_capability_preference: Some(input.capability.to_wire()),
    };
    let recovery = RecoverableWorkPreparation {
        authenticated_principal_id: session.authenticated_principal_id.clone(),
        session_id: session.session_id.clone(),
        request,
        confirm_idempotency_key: format!("guided-work-confirm:{}", Uuid::now_v7()),
    };
    match send(recovery.request.clone()).await {
        Ok(response) => match parse_guided_work_preparation(response, &recovery) {
            Ok(prepared) => Ok(GuidedWorkPreparationAttempt::Prepared(Box::new(prepared))),
            // PrepareWork can return a gateway error after Context Authority
            // committed but input-bundle persistence failed. Preserve the
            // exact request so callers can replay it instead of preparing a
            // replacement with a new idempotency key.
            Err(ClientGuidedWorkError::ApiOutcomeUnknown(_)) => Ok(
                GuidedWorkPreparationAttempt::OutcomeUnknown(Box::new(recovery)),
            ),
            Err(error) => Err(error),
        },
        Err(_) => Ok(GuidedWorkPreparationAttempt::OutcomeUnknown(Box::new(
            recovery,
        ))),
    }
}

fn parse_guided_work_preparation(
    response: PrepareWorkResponse,
    recovery: &RecoverableWorkPreparation,
) -> Result<PreparedWork, ClientGuidedWorkError> {
    let preview = match response.outcome {
        Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Preview(preview)) => preview,
        Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Error(error)) => {
            return Err(ClientGuidedWorkError::ApiOutcomeUnknown(Box::new(error)));
        }
        None => return Err(ClientGuidedWorkError::Protocol("prepare outcome missing")),
    };
    validate_guided_work_preview(
        &preview,
        &recovery.request.work_type,
        &recovery.request.target_scope_ref,
        guided_memory_mode_from_wire(recovery.request.memory_mode)?,
    )?;
    validate_guided_work_capability_choice(
        &preview,
        recovery.request.work_capability_preference.as_ref(),
    )?;
    let safe_preview = guided_work_safe_preview(
        &preview,
        guided_memory_mode_from_wire(recovery.request.memory_mode)?,
    )?;
    Ok(PreparedWork {
        authenticated_principal_id: recovery.authenticated_principal_id.clone(),
        session_id: recovery.session_id.clone(),
        preview,
        safe_preview,
        prepare_idempotency_key: recovery.request.idempotency_key.clone(),
        confirm_idempotency_key: recovery.confirm_idempotency_key.clone(),
    })
}

fn verify_guided_work_preparation_session(
    kernel: &ClientKernel,
    recovery: &RecoverableWorkPreparation,
) -> Result<(), ClientGuidedWorkError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(PREPARE_WORK_RPC, &session.granted_permission_codes)?;
    kernel
        .profiles()
        .authorize_rpc(CONFIRM_WORK_RPC, &session.granted_permission_codes)?;
    if session.session_id != recovery.session_id
        || session.authenticated_principal_id != recovery.authenticated_principal_id
    {
        return Err(ClientGuidedWorkError::SessionChanged);
    }
    Ok(())
}

async fn replay_guided_work_preparation_via<F, Fut>(
    kernel: &ClientKernel,
    recovery: &RecoverableWorkPreparation,
    send: F,
) -> Result<PreparedWork, ClientGuidedWorkError>
where
    F: FnOnce(PrepareWorkRequest) -> Fut,
    Fut: Future<Output = Result<PrepareWorkResponse, String>>,
{
    verify_guided_work_preparation_session(kernel, recovery)?;
    let response = send(recovery.request.clone())
        .await
        .map_err(ClientGuidedWorkError::PreparationOutcomeUnknown)?;
    parse_guided_work_preparation(response, recovery)
}

pub fn validate_guided_work_input(input: &GuidedWorkInput) -> Result<(), ClientGuidedWorkError> {
    if !is_guided_work_text(&input.intent, GUIDED_WORK_MAX_TEXT_BYTES) {
        return Err(ClientGuidedWorkError::InvalidInput(
            "intent must not be empty",
        ));
    }
    if !is_guided_work_text(&input.work_type, GUIDED_WORK_MAX_ROUTING_BYTES) {
        return Err(ClientGuidedWorkError::InvalidInput(
            "work_type is incomplete or too large",
        ));
    }
    if !is_guided_work_text(&input.target_scope_ref, GUIDED_WORK_MAX_ROUTING_BYTES) {
        return Err(ClientGuidedWorkError::InvalidInput(
            "target_scope_ref is incomplete or too large",
        ));
    }
    if input.sources.is_empty() && input.memory_mode == GuidedWorkMemoryMode::Disabled {
        return Err(ClientGuidedWorkError::InvalidInput(
            "add a context reference or enable memory",
        ));
    }
    if input.sources.len() > GUIDED_WORK_MAX_SOURCES
        || input.sources.iter().any(|source| {
            !is_guided_work_text(&source.source_ref, GUIDED_WORK_MAX_ROUTING_BYTES)
                || !is_guided_work_text(&source.label, GUIDED_WORK_MAX_ROUTING_BYTES)
        })
    {
        return Err(ClientGuidedWorkError::InvalidInput(
            "source count or source fields are invalid",
        ));
    }
    if let GuidedWorkCapabilityChoice::Explicit(choice_id) = &input.capability
        && !is_guided_work_text(choice_id, GUIDED_WORK_MAX_ROUTING_BYTES)
    {
        return Err(ClientGuidedWorkError::InvalidInput(
            "work capability choice is invalid",
        ));
    }
    let mut total_bytes = input
        .intent
        .len()
        .checked_add(input.work_type.len())
        .and_then(|value| value.checked_add(input.target_scope_ref.len()));
    for source in &input.sources {
        total_bytes = total_bytes
            .and_then(|value| value.checked_add(source.source_ref.len()))
            .and_then(|value| value.checked_add(source.label.len()));
    }
    if !matches!(total_bytes, Some(total) if total <= GUIDED_WORK_MAX_TEXT_BYTES) {
        return Err(ClientGuidedWorkError::InvalidInput(
            "guided work input is too large",
        ));
    }
    Ok(())
}

fn is_guided_work_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn parse_work_capability_catalog(
    result: ListWorkCapabilitiesResult,
) -> Result<GovernedWorkCapabilityCatalog, ClientWorkError> {
    let preference = result.preference.ok_or(ClientWorkError::Protocol(
        "work capability preference missing",
    ))?;
    if result.capabilities.is_empty()
        || result.capabilities.len() > 1_024
        || !is_guided_work_text(&preference.default_choice_id, GUIDED_WORK_MAX_ROUTING_BYTES)
        || preference.preference_revision == 0
    {
        return Err(ClientWorkError::Protocol(
            "work capability catalog is incomplete",
        ));
    }

    let mut choices = BTreeSet::new();
    let mut current_default_count = 0usize;
    let mut capabilities = Vec::with_capacity(result.capabilities.len());
    for view in result.capabilities {
        let capability = parse_work_capability_view(&view)?;
        if let Some(choice_id) = capability.choice_id.as_ref()
            && !choices.insert(choice_id.clone())
        {
            return Err(ClientWorkError::Protocol(
                "work capability choice identity is duplicated",
            ));
        }
        if capability.current_future_work_default {
            current_default_count += 1;
            if capability.choice_id.as_deref() != Some(preference.default_choice_id.as_str()) {
                return Err(ClientWorkError::Protocol(
                    "work capability default projection is inconsistent",
                ));
            }
        }
        capabilities.push(capability);
    }
    if current_default_count != 1 || !choices.contains(&preference.default_choice_id) {
        return Err(ClientWorkError::Protocol(
            "work capability default is not admitted",
        ));
    }
    Ok(GovernedWorkCapabilityCatalog {
        capabilities,
        default_choice_id: preference.default_choice_id,
        preference_revision: preference.preference_revision,
        configuration_migration_required: preference.configuration_migration_required,
    })
}

fn parse_work_capability_view(
    view: &WorkCapabilityView,
) -> Result<GovernedWorkCapability, ClientWorkError> {
    for value in [
        &view.provider_profile_id,
        &view.provider_alias,
        &view.harness_alias,
        &view.harness_model_alias,
        &view.provider_model_alias,
    ] {
        if !is_guided_work_text(value, GUIDED_WORK_MAX_ROUTING_BYTES) {
            return Err(ClientWorkError::Protocol(
                "work capability alias is invalid",
            ));
        }
    }
    if view
        .safe_reason_code
        .as_deref()
        .is_some_and(|value| !is_guided_work_text(value, GUIDED_WORK_MAX_ROUTING_BYTES))
        || view
            .choice_id
            .as_deref()
            .is_some_and(|value| !is_guided_work_text(value, GUIDED_WORK_MAX_ROUTING_BYTES))
    {
        return Err(ClientWorkError::Protocol(
            "work capability safe metadata is invalid",
        ));
    }

    let availability = match WorkCapabilityAvailability::try_from(view.availability) {
        Ok(WorkCapabilityAvailability::Admitted) => {
            let route = view
                .admitted_route
                .as_ref()
                .ok_or(ClientWorkError::Protocol(
                    "admitted work capability route missing",
                ))?;
            validate_work_capability_route_binding(route).map_err(|_| {
                ClientWorkError::Protocol("admitted work capability route is invalid")
            })?;
            if !view.selectable
                || view.safe_reason_code.is_some()
                || view.choice_id.is_none()
                || route.provider_profile_id != view.provider_profile_id
                || route.provider_id != view.provider_alias
                || route.harness_id != view.harness_alias
                || route.harness_model_id != view.harness_model_alias
                || route.provider_model_id != view.provider_model_alias
            {
                return Err(ClientWorkError::Protocol(
                    "admitted work capability projection is inconsistent",
                ));
            }
            GovernedWorkCapabilityAvailability::Admitted
        }
        Ok(WorkCapabilityAvailability::Candidate) => {
            if view.selectable
                || view.choice_id.is_some()
                || view.admitted_route.is_some()
                || view.current_future_work_default
                || view.safe_reason_code.is_none()
            {
                return Err(ClientWorkError::Protocol(
                    "candidate work capability became selectable",
                ));
            }
            GovernedWorkCapabilityAvailability::Candidate
        }
        Ok(WorkCapabilityAvailability::Held) => {
            if view.selectable
                || view.choice_id.is_some()
                || view.admitted_route.is_some()
                || view.current_future_work_default
                || view.safe_reason_code.is_none()
            {
                return Err(ClientWorkError::Protocol(
                    "held work capability became selectable",
                ));
            }
            GovernedWorkCapabilityAvailability::Held
        }
        Ok(WorkCapabilityAvailability::Unspecified) | Err(_) => {
            return Err(ClientWorkError::Protocol(
                "work capability availability is unknown",
            ));
        }
    };
    Ok(GovernedWorkCapability {
        provider_profile_id: view.provider_profile_id.clone(),
        provider_alias: view.provider_alias.clone(),
        harness_alias: view.harness_alias.clone(),
        harness_model_alias: view.harness_model_alias.clone(),
        provider_model_alias: view.provider_model_alias.clone(),
        availability,
        selectable: view.selectable,
        safe_reason_code: view.safe_reason_code.clone(),
        choice_id: view.choice_id.clone(),
        route_binding_sha256: view
            .admitted_route
            .as_ref()
            .map(|route| route.route_binding_sha256.clone()),
        current_future_work_default: view.current_future_work_default,
    })
}

fn validated_work_capability_selection(
    preview: &WorkPreparationPreview,
) -> Result<GovernedWorkCapabilitySelectionSource, ClientGuidedWorkError> {
    let view = preview
        .work_capability
        .as_ref()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work capability is missing",
        ))?;
    let capability = parse_work_capability_view(view)
        .map_err(|_| ClientGuidedWorkError::Protocol("prepared work capability is invalid"))?;
    if capability.availability != GovernedWorkCapabilityAvailability::Admitted
        || !capability.selectable
        || capability.choice_id.is_none()
        || capability.route_binding_sha256.is_none()
    {
        return Err(ClientGuidedWorkError::Protocol(
            "prepared work capability is not admitted",
        ));
    }

    match WorkCapabilitySelectionSource::try_from(preview.work_capability_selection_source) {
        Ok(WorkCapabilitySelectionSource::FutureWorkDefault) => {
            if !preview
                .preference_revision_at_resolution
                .is_some_and(|revision| revision > 0)
            {
                return Err(ClientGuidedWorkError::Protocol(
                    "prepared future-work default binding is incomplete",
                ));
            }
            Ok(GovernedWorkCapabilitySelectionSource::FutureWorkDefault)
        }
        Ok(WorkCapabilitySelectionSource::ExplicitChoice) => {
            if preview.preference_revision_at_resolution.is_some() {
                return Err(ClientGuidedWorkError::Protocol(
                    "explicit work capability unexpectedly depends on the mutable default",
                ));
            }
            Ok(GovernedWorkCapabilitySelectionSource::ExplicitChoice)
        }
        Ok(WorkCapabilitySelectionSource::LegacyOmittedDefault) => {
            if !preview
                .preference_revision_at_resolution
                .is_some_and(|revision| revision > 0)
            {
                return Err(ClientGuidedWorkError::Protocol(
                    "legacy work capability default binding is incomplete",
                ));
            }
            Ok(GovernedWorkCapabilitySelectionSource::LegacyOmittedDefault)
        }
        Ok(WorkCapabilitySelectionSource::Unspecified) | Err(_) => Err(
            ClientGuidedWorkError::Protocol("work capability selection source is unknown"),
        ),
    }
}

fn validate_guided_work_capability_choice(
    preview: &WorkPreparationPreview,
    requested: Option<&prepare_work_request::WorkCapabilityPreference>,
) -> Result<(), ClientGuidedWorkError> {
    let source = validated_work_capability_selection(preview)?;
    let view = preview
        .work_capability
        .as_ref()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work capability is missing",
        ))?;
    match (requested, source) {
        (
            Some(prepare_work_request::WorkCapabilityPreference::UseDefaultWorkCapability(_)),
            GovernedWorkCapabilitySelectionSource::FutureWorkDefault,
        )
        | (None, GovernedWorkCapabilitySelectionSource::LegacyOmittedDefault) => Ok(()),
        (
            Some(prepare_work_request::WorkCapabilityPreference::ExplicitWorkCapabilityChoiceId(
                requested_choice_id,
            )),
            GovernedWorkCapabilitySelectionSource::ExplicitChoice,
        ) if view.choice_id.as_deref() == Some(requested_choice_id.as_str()) => Ok(()),
        _ => Err(ClientGuidedWorkError::Protocol(
            "prepared work capability does not match the requested selection",
        )),
    }
}

fn validate_guided_work_preview(
    preview: &WorkPreparationPreview,
    expected_work_type: &str,
    expected_scope: &str,
    expected_memory_mode: GuidedWorkMemoryMode,
) -> Result<(), ClientGuidedWorkError> {
    let response_source_limit = GUIDED_WORK_MAX_SOURCES
        + if expected_memory_mode == GuidedWorkMemoryMode::GovernedRetrieval {
            WORK_MEMORY_MAX_RESULTS as usize
        } else {
            0
        };
    let project_source_count = preview
        .included_sources
        .iter()
        .filter(|source| source.authority == "project")
        .count()
        .checked_add(preview.excluded_sources.len());
    let memory_source_count = preview
        .included_sources
        .iter()
        .filter(|source| source.authority == "memory")
        .count();
    let canonical_snapshot_id = preview
        .snapshot_id
        .strip_prefix("ctx:")
        .is_some_and(is_canonical_sha256);
    let memory_binding_valid = match expected_memory_mode {
        GuidedWorkMemoryMode::Disabled => {
            preview.memory_authority_revision.is_none()
                && preview.memory_pack_snapshot_sha256.is_none()
        }
        GuidedWorkMemoryMode::GovernedRetrieval => {
            preview
                .memory_authority_revision
                .is_some_and(|revision| revision > 0)
                && preview
                    .memory_pack_snapshot_sha256
                    .as_deref()
                    .is_some_and(is_canonical_sha256)
        }
    };
    let capability_binding_valid = validated_work_capability_selection(preview).is_ok();
    let expected_gate_ready = preview.excluded_sources.is_empty()
        && (!preview.included_sources.is_empty()
            || expected_memory_mode == GuidedWorkMemoryMode::GovernedRetrieval);
    if !canonical_snapshot_id
        || preview.snapshot_revision == 0
        || preview.context_state_revision == 0
        || preview.work_type != expected_work_type
        || preview.target_scope_ref != expected_scope
        || !is_canonical_sha256(&preview.compiled_context_sha256)
        || !is_canonical_sha256(&preview.confirmation_binding_sha256)
        || preview.included_sources.len() > response_source_limit
        || preview.excluded_sources.len() > GUIDED_WORK_MAX_SOURCES
        || project_source_count.is_none_or(|count| count > GUIDED_WORK_MAX_SOURCES)
        || memory_source_count > WORK_MEMORY_MAX_RESULTS as usize
        || preview
            .included_sources
            .len()
            .checked_add(preview.excluded_sources.len())
            .is_none_or(|count| count > response_source_limit)
        || preview.blockers.len() > GUIDED_WORK_MAX_SOURCES
        || preview.warnings.len() > GUIDED_WORK_MAX_SOURCES
        || preview.non_goals
            != [
                "provider/model route cannot be selected or changed by model output",
                "memory is not mutated by preparation",
            ]
        || !is_guided_work_text(&preview.normalized_intent, GUIDED_WORK_MAX_TEXT_BYTES)
        || preview
            .non_goals
            .iter()
            .any(|value| safe_guided_work_non_goal(value).is_none())
        || preview.included_sources.iter().any(|source| {
            !is_guided_work_response_text(&source.source_ref)
                || !is_guided_work_response_text(&source.label)
                || !matches!(source.authority.as_str(), "project" | "memory")
                || (source.authority == "memory"
                    && expected_memory_mode != GuidedWorkMemoryMode::GovernedRetrieval)
                || !is_canonical_sha256(&source.content_sha256)
                || !source.included
        })
        || preview
            .excluded_sources
            .iter()
            .any(|notice| !is_valid_guided_work_excluded_source(notice))
        || preview.blockers != preview.excluded_sources
        || preview
            .blockers
            .iter()
            .any(|notice| safe_guided_work_blocker(&notice.code).is_none())
        || preview
            .warnings
            .iter()
            .any(|notice| !is_valid_guided_work_warning(notice))
        || (expected_memory_mode == GuidedWorkMemoryMode::Disabled && !preview.warnings.is_empty())
        || !memory_binding_valid
        || !capability_binding_valid
        || preview.gate_ready != preview.ready_for_founder_confirmation
        || preview.gate_ready != expected_gate_ready
    {
        return Err(ClientGuidedWorkError::Protocol(
            "prepared work binding is incomplete",
        ));
    }
    Ok(())
}

fn guided_memory_mode_from_wire(value: i32) -> Result<GuidedWorkMemoryMode, ClientGuidedWorkError> {
    match WorkMemoryMode::try_from(value) {
        Ok(WorkMemoryMode::Disabled) => Ok(GuidedWorkMemoryMode::Disabled),
        Ok(WorkMemoryMode::GovernedRetrieval) => Ok(GuidedWorkMemoryMode::GovernedRetrieval),
        Ok(WorkMemoryMode::Unspecified) | Err(_) => Err(ClientGuidedWorkError::Protocol(
            "guided work memory mode is incomplete",
        )),
    }
}

fn is_guided_work_response_text(value: &str) -> bool {
    value == value.trim() && is_guided_work_text(value, GUIDED_WORK_MAX_ROUTING_BYTES)
}

fn safe_guided_work_blocker(value: &str) -> Option<GovernedWorkNotice> {
    match value {
        "CONTEXT_SOURCE_EMPTY" => Some(GovernedWorkNotice::ContextSourceEmpty),
        "CONTEXT_SOURCE_OUTSIDE_WORKSPACE" => {
            Some(GovernedWorkNotice::ContextSourceOutsideWorkspace)
        }
        "CONTEXT_SOURCE_UNREADABLE" => Some(GovernedWorkNotice::ContextSourceUnreadable),
        "CONTEXT_SOURCE_TOO_LARGE" => Some(GovernedWorkNotice::ContextSourceTooLarge),
        _ => None,
    }
}

fn safe_guided_work_warning(value: &str) -> Option<GovernedWorkNotice> {
    match value {
        "MEMORY_RETRIEVAL_EMPTY" => Some(GovernedWorkNotice::MemoryRetrievalEmpty),
        "MEMORY_CONTENT_BUDGET_EXCLUDED" => Some(GovernedWorkNotice::MemoryContentBudgetExcluded),
        _ => None,
    }
}

fn safe_guided_work_non_goal(value: &str) -> Option<GuidedWorkNonGoal> {
    match value {
        "provider/model route cannot be selected or changed by model output" => {
            Some(GuidedWorkNonGoal::ProviderRouteCannotBeModelSelected)
        }
        "memory is not mutated by preparation" => Some(GuidedWorkNonGoal::MemoryMutationExcluded),
        _ => None,
    }
}

fn is_valid_guided_work_excluded_source(
    notice: &egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkGateNotice,
) -> bool {
    match safe_guided_work_blocker(&notice.code) {
        Some(GovernedWorkNotice::ContextSourceEmpty) => {
            notice.source_ref.is_empty() && notice.detail == "source_ref must not be empty"
        }
        Some(_) => {
            is_guided_work_response_text(&notice.source_ref) && notice.detail == notice.source_ref
        }
        None => false,
    }
}

fn is_valid_guided_work_warning(
    notice: &egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkGateNotice,
) -> bool {
    match safe_guided_work_warning(&notice.code) {
        Some(GovernedWorkNotice::MemoryRetrievalEmpty) => {
            is_guided_work_response_text(&notice.source_ref)
                && notice.detail == "governed retrieval completed with no matching accepted records"
        }
        Some(GovernedWorkNotice::MemoryContentBudgetExcluded) => {
            is_guided_work_response_text(&notice.source_ref)
                && notice.detail
                    == format!(
                        "rank-prefix exceeded {} UTF-8 bytes",
                        WORK_MEMORY_MAX_SELECTED_CONTENT_BYTES
                    )
        }
        Some(_) | None => false,
    }
}

fn guided_work_safe_preview(
    preview: &WorkPreparationPreview,
    memory_mode: GuidedWorkMemoryMode,
) -> Result<GuidedWorkPreview, ClientGuidedWorkError> {
    let non_goals = preview
        .non_goals
        .iter()
        .map(|value| safe_guided_work_non_goal(value))
        .collect::<Option<Vec<_>>>()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work contains an unknown non-goal",
        ))?;
    let blockers = preview
        .blockers
        .iter()
        .map(|notice| safe_guided_work_blocker(&notice.code))
        .collect::<Option<Vec<_>>>()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work contains an unknown blocker",
        ))?;
    let warnings = preview
        .warnings
        .iter()
        .map(|notice| safe_guided_work_warning(&notice.code))
        .collect::<Option<Vec<_>>>()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work contains an unknown warning",
        ))?;
    let capability_selection_source = validated_work_capability_selection(preview)?;
    let capability = preview
        .work_capability
        .as_ref()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work capability is missing",
        ))?;
    let route = capability
        .admitted_route
        .as_ref()
        .ok_or(ClientGuidedWorkError::Protocol(
            "prepared work capability route is missing",
        ))?;
    Ok(GuidedWorkPreview {
        normalized_intent: preview.normalized_intent.clone(),
        work_type: preview.work_type.clone(),
        target_scope_ref: preview.target_scope_ref.clone(),
        non_goals,
        included_source_count: preview.included_sources.len(),
        excluded_source_count: preview.excluded_sources.len(),
        blockers,
        warnings,
        memory_mode,
        memory_authority_revision: preview.memory_authority_revision,
        memory_pack_snapshot_sha256: preview.memory_pack_snapshot_sha256.clone(),
        capability_choice_id: capability.choice_id.clone().ok_or(
            ClientGuidedWorkError::Protocol("prepared work capability choice is missing"),
        )?,
        provider_alias: capability.provider_alias.clone(),
        harness_alias: capability.harness_alias.clone(),
        harness_model_alias: capability.harness_model_alias.clone(),
        provider_model_alias: capability.provider_model_alias.clone(),
        route_binding_sha256: route.route_binding_sha256.clone(),
        capability_selection_source,
        preference_revision_at_resolution: preview.preference_revision_at_resolution,
        gate_ready: preview.gate_ready,
        ready_for_founder_confirmation: preview.ready_for_founder_confirmation,
    })
}

fn seal_guided_work_confirmation(
    kernel: &ClientKernel,
    prepared: PreparedWork,
    now: SystemTime,
) -> Result<RecoverableWorkConfirmation, ClientGuidedWorkError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(CONFIRM_WORK_RPC, &session.granted_permission_codes)?;
    if session.session_id != prepared.session_id
        || session.authenticated_principal_id != prepared.authenticated_principal_id
    {
        return Err(ClientGuidedWorkError::SessionChanged);
    }
    validate_guided_work_preview(
        &prepared.preview,
        &prepared.safe_preview.work_type,
        &prepared.safe_preview.target_scope_ref,
        prepared.safe_preview.memory_mode,
    )?;
    if guided_work_safe_preview(&prepared.preview, prepared.safe_preview.memory_mode)?
        != prepared.safe_preview
    {
        return Err(ClientGuidedWorkError::BindingChanged);
    }
    if prepared.prepare_idempotency_key.trim().is_empty() {
        return Err(ClientGuidedWorkError::BindingChanged);
    }
    if !prepared.preview.gate_ready
        || !prepared.preview.ready_for_founder_confirmation
        || !prepared.preview.blockers.is_empty()
    {
        return Err(ClientGuidedWorkError::Blocked);
    }
    let request = ConfirmWorkRequest {
        client: Some(kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?),
        snapshot_id: prepared.preview.snapshot_id.clone(),
        confirmation_binding_sha256: prepared.preview.confirmation_binding_sha256,
        idempotency_key: prepared.confirm_idempotency_key,
    };
    Ok(RecoverableWorkConfirmation {
        authenticated_principal_id: prepared.authenticated_principal_id,
        session_id: prepared.session_id,
        expected_snapshot_id: request.snapshot_id.clone(),
        expected_confirmation_binding_sha256: request.confirmation_binding_sha256.clone(),
        expected_work_type: prepared.preview.work_type,
        expected_target_scope_ref: prepared.preview.target_scope_ref,
        request,
    })
}

async fn confirm_guided_work_via<F, Fut>(
    kernel: &ClientKernel,
    prepared: PreparedWork,
    now: SystemTime,
    send: F,
) -> Result<GuidedWorkConfirmationAttempt, ClientGuidedWorkError>
where
    F: FnOnce(ConfirmWorkRequest) -> Fut,
    Fut: Future<Output = Result<ConfirmWorkResponse, String>>,
{
    let recovery = seal_guided_work_confirmation(kernel, prepared, now)?;
    match send(recovery.request.clone()).await {
        Ok(response) => match parse_guided_work_confirmation(response, &recovery) {
            Ok(confirmed) => Ok(GuidedWorkConfirmationAttempt::Confirmed(Box::new(
                confirmed,
            ))),
            // ConfirmWork can return a gateway error after Task Authority
            // committed but await-token creation failed. Preserve the exact
            // command; the caller must replay it, not prepare again.
            Err(ClientGuidedWorkError::ApiOutcomeUnknown(_)) => Ok(
                GuidedWorkConfirmationAttempt::OutcomeUnknown(Box::new(recovery)),
            ),
            Err(error) => Err(error),
        },
        Err(_) => Ok(GuidedWorkConfirmationAttempt::OutcomeUnknown(Box::new(
            recovery,
        ))),
    }
}

async fn replay_guided_work_confirmation_via<F, Fut>(
    kernel: &ClientKernel,
    recovery: &RecoverableWorkConfirmation,
    send: F,
) -> Result<ConfirmedWork, ClientGuidedWorkError>
where
    F: FnOnce(ConfirmWorkRequest) -> Fut,
    Fut: Future<Output = Result<ConfirmWorkResponse, String>>,
{
    verify_guided_work_recovery_session(kernel, recovery)?;
    let response = send(recovery.request.clone())
        .await
        .map_err(ClientGuidedWorkError::ConfirmationOutcomeUnknown)?;
    parse_guided_work_confirmation(response, recovery)
}

fn verify_guided_work_recovery_session(
    kernel: &ClientKernel,
    recovery: &RecoverableWorkConfirmation,
) -> Result<(), ClientGuidedWorkError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(CONFIRM_WORK_RPC, &session.granted_permission_codes)?;
    if session.session_id != recovery.session_id
        || session.authenticated_principal_id != recovery.authenticated_principal_id
    {
        return Err(ClientGuidedWorkError::SessionChanged);
    }
    if recovery.request.snapshot_id != recovery.expected_snapshot_id
        || recovery.request.confirmation_binding_sha256
            != recovery.expected_confirmation_binding_sha256
        || !is_canonical_sha256(&recovery.expected_confirmation_binding_sha256)
        || recovery.request.idempotency_key.trim().is_empty()
    {
        return Err(ClientGuidedWorkError::BindingChanged);
    }
    Ok(())
}

fn parse_guided_work_confirmation(
    response: ConfirmWorkResponse,
    recovery: &RecoverableWorkConfirmation,
) -> Result<ConfirmedWork, ClientGuidedWorkError> {
    let accepted = match response.outcome {
        Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Accepted(accepted)) => accepted,
        Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Error(error)) => {
            return Err(ClientGuidedWorkError::ApiOutcomeUnknown(Box::new(error)));
        }
        None => return Err(ClientGuidedWorkError::Protocol("confirm outcome missing")),
    };
    let result = accepted
        .authority_result
        .ok_or(ClientGuidedWorkError::Protocol(
            "confirmed task result missing",
        ))?;
    match result.outcome.as_ref() {
        Some(task_command_result::Outcome::Task(task))
            if task.task_id.trim().is_empty()
                || task.input_snapshot_id != recovery.expected_snapshot_id
                || task.work_type != recovery.expected_work_type
                || task.target_scope_ref != recovery.expected_target_scope_ref =>
        {
            return Err(ClientGuidedWorkError::Protocol(
                "confirmed task binding changed",
            ));
        }
        Some(task_command_result::Outcome::Task(_)) => {}
        Some(task_command_result::Outcome::Error(error)) => {
            return Err(ClientGuidedWorkError::Authority {
                error_code: error.code,
                safe_detail_code: error.safe_detail_code.clone(),
            });
        }
        None => {
            return Err(ClientGuidedWorkError::Protocol(
                "confirmed task authority outcome missing",
            ));
        }
    }
    Ok(ConfirmedWork {
        result,
        await_token: accepted.await_token,
    })
}

async fn open_approval_stream_via<F, Fut, S>(
    kernel: &ClientKernel,
    resume_after: Option<ProjectionPosition>,
    now: SystemTime,
    dispatch: F,
) -> Result<S, ClientApprovalWatchError>
where
    F: FnOnce(WatchHarnessApprovalViewsRequest) -> Fut,
    Fut: Future<Output = Result<S, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_rpc(
        WATCH_HARNESS_APPROVAL_VIEWS_RPC,
        &session.granted_permission_codes,
    )?;
    let metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    dispatch(approval_watch_wire_request(metadata, resume_after))
        .await
        .map_err(ClientApprovalWatchError::Transport)
}

async fn read_task_result_review_via<T, TFut, E, EFut>(
    kernel: &ClientKernel,
    task_id: &str,
    now: SystemTime,
    get_task: T,
    get_evidence: E,
) -> Result<TaskResultReview, ClientTaskResultReviewError>
where
    T: FnOnce(GetTaskViewRequest) -> TFut,
    TFut: Future<Output = Result<GetTaskViewResponse, String>>,
    E: FnOnce(GetEvidenceGraphRequest) -> EFut,
    EFut: Future<Output = Result<GetEvidenceGraphResponse, String>>,
{
    if task_id.trim().is_empty() {
        return Err(ClientTaskResultReviewError::InvalidInput(
            "task_id must not be empty",
        ));
    }
    authorize_review_rpc(kernel, GET_TASK_VIEW_RPC, TaskResultReviewStage::Task)?;
    let task_response = get_task(GetTaskViewRequest {
        client: Some(review_metadata(kernel, now, TaskResultReviewStage::Task)?),
        task_id: task_id.to_owned(),
        minimum_position: None,
    })
    .await
    .map_err(|detail| ClientTaskResultReviewError::Transport {
        stage: TaskResultReviewStage::Task,
        detail,
    })?;
    let task_view = match task_response.outcome {
        Some(get_task_view_response::Outcome::View(view)) => view,
        Some(get_task_view_response::Outcome::Error(error)) => {
            return Err(ClientTaskResultReviewError::Api {
                stage: TaskResultReviewStage::Task,
                error: Box::new(error),
            });
        }
        None => {
            return Err(review_integrity(
                TaskResultReviewStage::Task,
                "task view outcome missing",
            ));
        }
    };
    let (task_position, artifact_set_id) = validate_task_result_view(&task_view, task_id)?;
    let Some(artifact_set_id) = artifact_set_id else {
        return Ok(TaskResultReview {
            task_view,
            evidence_graph: None,
        });
    };

    authorize_review_rpc(
        kernel,
        GET_EVIDENCE_GRAPH_RPC,
        TaskResultReviewStage::Evidence,
    )?;
    let evidence_response = get_evidence(GetEvidenceGraphRequest {
        client: Some(review_metadata(
            kernel,
            now,
            TaskResultReviewStage::Evidence,
        )?),
        task_id: task_id.to_owned(),
        artifact_set_id: artifact_set_id.clone(),
        minimum_position: Some(task_position),
    })
    .await
    .map_err(|detail| ClientTaskResultReviewError::Transport {
        stage: TaskResultReviewStage::Evidence,
        detail,
    })?;
    let graph = match evidence_response.outcome {
        Some(get_evidence_graph_response::Outcome::Graph(graph)) => graph,
        Some(get_evidence_graph_response::Outcome::Error(error)) => {
            return Err(ClientTaskResultReviewError::Api {
                stage: TaskResultReviewStage::Evidence,
                error: Box::new(error),
            });
        }
        None => {
            return Err(review_integrity(
                TaskResultReviewStage::Evidence,
                "evidence graph outcome missing",
            ));
        }
    };
    validate_evidence_graph(&task_view, &graph, task_id, &artifact_set_id)?;
    Ok(TaskResultReview {
        task_view,
        evidence_graph: Some(graph),
    })
}

fn authorize_review_rpc(
    kernel: &ClientKernel,
    rpc: &str,
    stage: TaskResultReviewStage,
) -> Result<(), ClientTaskResultReviewError> {
    let session = kernel
        .session()
        .ok_or(KernelError::SessionUnavailable)
        .map_err(|source| ClientTaskResultReviewError::Kernel { stage, source })?;
    kernel
        .profiles()
        .authorize_rpc(rpc, &session.granted_permission_codes)
        .map(|_| ())
        .map_err(|source| ClientTaskResultReviewError::Kernel { stage, source })
}

fn review_metadata(
    kernel: &ClientKernel,
    now: SystemTime,
    stage: TaskResultReviewStage,
) -> Result<ClientRequestMetadata, ClientTaskResultReviewError> {
    kernel
        .request_metadata(Uuid::now_v7().to_string(), None, now)
        .map_err(|source| ClientTaskResultReviewError::Kernel { stage, source })
}

fn review_integrity(
    stage: TaskResultReviewStage,
    detail: &'static str,
) -> ClientTaskResultReviewError {
    ClientTaskResultReviewError::Integrity { stage, detail }
}

fn validate_projection_metadata(
    metadata: Option<&ProjectionMetadata>,
    stage: TaskResultReviewStage,
) -> Result<ProjectionPosition, ClientTaskResultReviewError> {
    let metadata =
        metadata.ok_or_else(|| review_integrity(stage, "projection metadata missing"))?;
    if metadata.stale || metadata.health != ProjectionHealth::Ready as i32 {
        return Err(review_integrity(
            stage,
            "projection is not ready and current",
        ));
    }
    let position = metadata
        .position
        .as_ref()
        .ok_or_else(|| review_integrity(stage, "projection position missing"))?;
    if position.epoch.is_empty() || position.sequence == 0 {
        return Err(review_integrity(stage, "projection position invalid"));
    }
    let mut sources = BTreeSet::new();
    for source in &metadata.source_revisions {
        if SourceDomain::try_from(source.domain).is_err()
            || source.domain == SourceDomain::Unspecified as i32
            || source.aggregate_id.is_empty()
            || source.revision == 0
            || source.last_event_id.is_empty()
            || !sources.insert((source.domain, source.aggregate_id.as_str()))
        {
            return Err(review_integrity(
                stage,
                "projection source revision invalid",
            ));
        }
    }
    Ok(position.clone())
}

fn exact_source<'a>(
    metadata: &'a ProjectionMetadata,
    domain: SourceDomain,
    aggregate_id: &str,
    stage: TaskResultReviewStage,
) -> Result<&'a SourceRevision, ClientTaskResultReviewError> {
    let mut matches = metadata
        .source_revisions
        .iter()
        .filter(|source| source.domain == domain as i32 && source.aggregate_id == aggregate_id);
    let source = matches
        .next()
        .ok_or_else(|| review_integrity(stage, "required projection source missing"))?;
    if matches.next().is_some() {
        return Err(review_integrity(stage, "projection source duplicated"));
    }
    Ok(source)
}

fn validate_task_result_view(
    view: &TaskView,
    expected_task_id: &str,
) -> Result<(ProjectionPosition, Option<String>), ClientTaskResultReviewError> {
    let stage = TaskResultReviewStage::Task;
    let position = validate_projection_metadata(view.metadata.as_ref(), stage)?;
    let metadata = view.metadata.as_ref().expect("metadata validated");
    let task = view
        .task
        .as_ref()
        .ok_or_else(|| review_integrity(stage, "task snapshot missing"))?;
    if task.task_id != expected_task_id
        || task.task_id.is_empty()
        || task.revision == 0
        || DomainTaskStatus::try_from(task.status).is_err()
        || task.status == DomainTaskStatus::Unspecified as i32
    {
        return Err(review_integrity(stage, "task identity mismatch"));
    }
    let task_source = exact_source(metadata, SourceDomain::Task, expected_task_id, stage)?;
    if task_source.revision != task.revision {
        return Err(review_integrity(stage, "task source revision mismatch"));
    }

    let artifact_set_id = match (&task.artifact_set_id, &view.artifact_set) {
        (None, None) => None,
        (Some(id), Some(set)) if !id.is_empty() && set.artifact_set_id == *id => {
            let lineage = set
                .lineage
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "ArtifactSet lineage missing"))?;
            if set.revision == 0
                || ArtifactSetStatus::try_from(set.status).is_err()
                || set.status == ArtifactSetStatus::Unspecified as i32
                || !result_lineage_is_complete(lineage)
                || lineage.task_id != task.task_id
                || lineage.work_revision != task.work_revision
            {
                return Err(review_integrity(stage, "ArtifactSet binding mismatch"));
            }
            let set_source = exact_source(metadata, SourceDomain::Artifact, id, stage)?;
            if set_source.revision != set.revision {
                return Err(review_integrity(
                    stage,
                    "ArtifactSet source revision mismatch",
                ));
            }
            Some(id.clone())
        }
        _ => {
            return Err(review_integrity(
                stage,
                "ArtifactSet presence or identity mismatch",
            ));
        }
    };

    match (&task.verification_artifact_id, &view.verification) {
        (None, None) => {}
        (Some(id), Some(verification))
            if !id.is_empty() && verification.verification_artifact_id == *id =>
        {
            let binding = verification
                .binding
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "Verification binding missing"))?;
            let lineage = binding
                .lineage
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "Verification lineage missing"))?;
            let set = view
                .artifact_set
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "Verification ArtifactSet missing"))?;
            let set_lineage = set
                .lineage
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "ArtifactSet lineage missing"))?;
            if verification.version == 0
                || VerificationConclusion::try_from(verification.conclusion).is_err()
                || verification.conclusion == VerificationConclusion::Unspecified as i32
                || lineage != set_lineage
                || binding.artifact_set_id != set.artifact_set_id
                || binding.artifact_set_manifest != set.canonical_manifest
                || binding.acceptance_contract_ref != task.acceptance_contract_ref
                || (!binding.claim_id.is_empty() && !set.claim_ids.contains(&binding.claim_id))
            {
                return Err(review_integrity(stage, "Verification binding mismatch"));
            }
            let source = exact_source(metadata, SourceDomain::Verification, id, stage)?;
            if source.revision != verification.version {
                return Err(review_integrity(
                    stage,
                    "Verification source revision mismatch",
                ));
            }
        }
        _ => {
            return Err(review_integrity(
                stage,
                "Verification presence or identity mismatch",
            ));
        }
    }

    match (
        &task.founder_verdict_id,
        &view.founder_verdict,
        &view.founder_verdict_state,
    ) {
        (None, None, None) => {}
        (Some(id), Some(verdict), Some(state))
            if !id.is_empty()
                && verdict.founder_verdict_id == *id
                && state.founder_verdict_id == *id =>
        {
            let scope = verdict
                .scope
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "Founder Verdict scope missing"))?;
            let verification = view
                .verification
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "Founder Verdict verification missing"))?;
            let set = view
                .artifact_set
                .as_ref()
                .ok_or_else(|| review_integrity(stage, "Founder Verdict ArtifactSet missing"))?;
            if verdict.version == 0
                || state.revision == 0
                || FounderVerdictDecision::try_from(verdict.decision).is_err()
                || verdict.decision == FounderVerdictDecision::Unspecified as i32
                || FounderVerdictStateKind::try_from(state.state).is_err()
                || state.state == FounderVerdictStateKind::Unspecified as i32
                || scope.task_id != task.task_id
                || scope.work_revision != task.work_revision
                || scope.artifact_set_id != set.artifact_set_id
                || scope.artifact_set_manifest != set.canonical_manifest
                || scope.verification_artifact_id != verification.verification_artifact_id
                || scope.verification_payload != verification.canonical_payload
                || scope.acceptance_contract_ref != task.acceptance_contract_ref
                || verdict.observed_verification_conclusion != verification.conclusion
            {
                return Err(review_integrity(stage, "Founder Verdict binding mismatch"));
            }
            let source = exact_source(metadata, SourceDomain::FounderVerdict, id, stage)?;
            if source.revision != state.revision {
                return Err(review_integrity(
                    stage,
                    "Founder Verdict source revision mismatch",
                ));
            }
        }
        _ => {
            return Err(review_integrity(
                stage,
                "Founder Verdict presence or identity mismatch",
            ));
        }
    }
    Ok((position, artifact_set_id))
}

fn result_lineage_is_complete(
    lineage: &egopulse_domain_contracts::v01::egopulse::artifact::v1::LineageBinding,
) -> bool {
    !lineage.task_id.is_empty()
        && lineage.task_revision > 0
        && lineage.work_revision > 0
        && !lineage.run_id.is_empty()
        && lineage.run_revision > 0
        && !lineage.step_id.is_empty()
        && lineage.step_revision > 0
        && !lineage.attempt_id.is_empty()
        && lineage.attempt_revision > 0
        && !lineage.dispatch_id.is_empty()
        && lineage.fencing_token > 0
}

fn unique_ids<'a>(
    values: impl IntoIterator<Item = &'a str>,
    stage: TaskResultReviewStage,
) -> Result<BTreeSet<&'a str>, ClientTaskResultReviewError> {
    let mut ids = BTreeSet::new();
    for value in values {
        if value.is_empty() || !ids.insert(value) {
            return Err(review_integrity(stage, "evidence graph membership invalid"));
        }
    }
    Ok(ids)
}

fn validate_evidence_graph(
    task_view: &TaskView,
    graph: &EvidenceGraphView,
    expected_task_id: &str,
    expected_artifact_set_id: &str,
) -> Result<(), ClientTaskResultReviewError> {
    let stage = TaskResultReviewStage::Evidence;
    let task_position = task_view
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.position.as_ref())
        .expect("Task projection validated");
    let graph_position = validate_projection_metadata(graph.metadata.as_ref(), stage)?;
    if graph.task_id != expected_task_id
        || graph.artifact_set_id != expected_artifact_set_id
        || graph_position.epoch != task_position.epoch
    {
        return Err(review_integrity(stage, "evidence graph binding mismatch"));
    }
    let task_metadata = task_view
        .metadata
        .as_ref()
        .expect("Task metadata validated");
    let graph_metadata = graph.metadata.as_ref().expect("graph metadata validated");
    let task_set_source = exact_source(
        task_metadata,
        SourceDomain::Artifact,
        expected_artifact_set_id,
        stage,
    )?;
    let graph_set_source = exact_source(
        graph_metadata,
        SourceDomain::Artifact,
        expected_artifact_set_id,
        stage,
    )?;
    if task_set_source != graph_set_source {
        return Err(review_integrity(stage, "ArtifactSet source tuple mismatch"));
    }

    let set = task_view
        .artifact_set
        .as_ref()
        .expect("ArtifactSet validated");
    let set_lineage = set.lineage.as_ref().expect("ArtifactSet lineage validated");
    let expected_artifacts = unique_ids(set.artifact_ids.iter().map(String::as_str), stage)?;
    let expected_claims = unique_ids(set.claim_ids.iter().map(String::as_str), stage)?;
    let expected_evidence = unique_ids(set.evidence_ids.iter().map(String::as_str), stage)?;
    let actual_artifacts = unique_ids(
        graph
            .artifacts
            .iter()
            .map(|value| value.artifact_id.as_str()),
        stage,
    )?;
    let actual_claims = unique_ids(
        graph.claims.iter().map(|value| value.claim_id.as_str()),
        stage,
    )?;
    let actual_evidence = unique_ids(
        graph
            .evidence
            .iter()
            .map(|value| value.evidence_id.as_str()),
        stage,
    )?;
    if expected_artifacts != actual_artifacts
        || expected_claims != actual_claims
        || expected_evidence != actual_evidence
    {
        return Err(review_integrity(
            stage,
            "evidence graph membership mismatch",
        ));
    }
    let mut expected_sources = BTreeSet::from([expected_artifact_set_id]);
    expected_sources.extend(expected_artifacts.iter().copied());
    expected_sources.extend(expected_claims.iter().copied());
    expected_sources.extend(expected_evidence.iter().copied());
    if graph_metadata.source_revisions.len() != expected_sources.len()
        || graph_metadata.source_revisions.iter().any(|source| {
            source.domain != SourceDomain::Artifact as i32
                || !expected_sources.contains(source.aggregate_id.as_str())
        })
    {
        return Err(review_integrity(
            stage,
            "evidence graph source membership mismatch",
        ));
    }

    for artifact in &graph.artifacts {
        let source = exact_source(
            graph_metadata,
            SourceDomain::Artifact,
            &artifact.artifact_id,
            stage,
        )?;
        let lineage = artifact
            .provenance
            .as_ref()
            .and_then(|value| value.lineage.as_ref())
            .ok_or_else(|| review_integrity(stage, "artifact lineage missing"))?;
        if artifact.revision == 0 || source.revision != artifact.revision || lineage != set_lineage
        {
            return Err(review_integrity(stage, "artifact lineage mismatch"));
        }
    }
    for claim in &graph.claims {
        let source = exact_source(
            graph_metadata,
            SourceDomain::Artifact,
            &claim.claim_id,
            stage,
        )?;
        let lineage = claim
            .lineage
            .as_ref()
            .ok_or_else(|| review_integrity(stage, "claim lineage missing"))?;
        let claim_artifact_ids =
            unique_ids(claim.subject_artifact_ids.iter().map(String::as_str), stage)?;
        if claim.revision == 0
            || source.revision != claim.revision
            || lineage != set_lineage
            || claim_artifact_ids
                .iter()
                .any(|id| !actual_artifacts.contains(id))
        {
            return Err(review_integrity(stage, "claim reference mismatch"));
        }
    }
    for evidence in &graph.evidence {
        let source = exact_source(
            graph_metadata,
            SourceDomain::Artifact,
            &evidence.evidence_id,
            stage,
        )?;
        let lineage = evidence
            .lineage
            .as_ref()
            .ok_or_else(|| review_integrity(stage, "evidence lineage missing"))?;
        let evidence_artifact_ids =
            unique_ids(evidence.artifact_ids.iter().map(String::as_str), stage)?;
        if evidence.revision == 0
            || source.revision != evidence.revision
            || lineage != set_lineage
            || !actual_claims.contains(evidence.claim_id.as_str())
            || evidence_artifact_ids
                .iter()
                .any(|id| !actual_artifacts.contains(id))
        {
            return Err(review_integrity(stage, "evidence reference mismatch"));
        }
    }
    Ok(())
}

/// Builds the existing `ExecuteFounderVerdict` payload from a trusted result
/// review. The caller supplies stable command/idempotency metadata and the
/// explicit confirmation proof; this function never invents supporting
/// Artifact identifiers for decisions that require them.
pub fn build_guided_founder_verdict(
    review: &TaskResultReview,
    input: GuidedFounderVerdictInput,
) -> Result<VerdictCommand, ClientGuidedFounderVerdictError> {
    build_guided_founder_verdict_inner(review, input, None)
}

/// Builds Rework or risk-accepting Founder Verdicts from receipts confirmed by
/// the supporting-material RPC. Artifact identifiers and coverage are derived
/// from those private confirmation capsules rather than accepted as input.
pub fn build_guided_founder_verdict_with_materials(
    review: &TaskResultReview,
    input: GuidedFounderVerdictInput,
    session: &egopulse_client_kernel::SessionBinding,
    materials: &FounderSupportingMaterialCollection,
) -> Result<VerdictCommand, ClientGuidedFounderVerdictError> {
    if session.authenticated_principal_id.trim().is_empty() || session.session_id.trim().is_empty()
    {
        return Err(ClientGuidedFounderVerdictError::InvalidInput(
            "authenticated Founder session must be complete",
        ));
    }
    build_guided_founder_verdict_inner(
        review,
        input,
        Some((session.authenticated_principal_id.as_str(), materials)),
    )
}

fn build_guided_founder_verdict_inner(
    review: &TaskResultReview,
    input: GuidedFounderVerdictInput,
    confirmed_materials: Option<(&str, &FounderSupportingMaterialCollection)>,
) -> Result<VerdictCommand, ClientGuidedFounderVerdictError> {
    if input.current_task_id.trim().is_empty() {
        return Err(ClientGuidedFounderVerdictError::InvalidInput(
            "current_task_id must not be empty",
        ));
    }
    validate_guided_verdict_metadata(&input.metadata)?;
    if input.confirmation_proof_ref.trim().is_empty() {
        return Err(ClientGuidedFounderVerdictError::InvalidInput(
            "confirmation_proof_ref must come from an explicit user confirmation",
        ));
    }
    if !guided_verdict_timestamp_is_valid(&input.expires_at)
        || input.metadata.issued_at.as_ref().is_none_or(|issued_at| {
            (input.expires_at.seconds, input.expires_at.nanos)
                <= (issued_at.seconds, issued_at.nanos)
        })
    {
        return Err(ClientGuidedFounderVerdictError::InvalidInput(
            "expires_at must be later than the caller-supplied issued_at",
        ));
    }

    let (_, artifact_set_id) =
        validate_task_result_view(&review.task_view, &input.current_task_id)?;
    let artifact_set_id = artifact_set_id.ok_or(
        ClientGuidedFounderVerdictError::MissingMaterial("current ArtifactSet"),
    )?;
    let graph =
        review
            .evidence_graph
            .as_ref()
            .ok_or(ClientGuidedFounderVerdictError::MissingMaterial(
                "current EvidenceGraph for the selected ArtifactSet",
            ))?;
    validate_evidence_graph(
        &review.task_view,
        graph,
        &input.current_task_id,
        &artifact_set_id,
    )?;

    let task = review
        .task_view
        .task
        .as_ref()
        .expect("Task result review validation requires a Task snapshot");
    validate_founder_verdict_action(&review.task_view)
        .map_err(ClientGuidedFounderVerdictError::NonActionable)?;

    let artifact_set = review
        .task_view
        .artifact_set
        .as_ref()
        .expect("Task result review validation requires the bound ArtifactSet");
    if artifact_set.status != ArtifactSetStatus::Sealed as i32 {
        return Err(ClientGuidedFounderVerdictError::MissingMaterial(
            "sealed current ArtifactSet",
        ));
    }
    let artifact_set_manifest = artifact_set
        .canonical_manifest
        .clone()
        .filter(guided_verdict_content_address_is_complete)
        .ok_or(ClientGuidedFounderVerdictError::MissingMaterial(
            "sealed ArtifactSet canonical manifest",
        ))?;
    let verification = review.task_view.verification.as_ref().ok_or(
        ClientGuidedFounderVerdictError::MissingMaterial("current VerificationArtifact"),
    )?;
    let conclusion = VerificationConclusion::try_from(verification.conclusion).map_err(|_| {
        ClientGuidedFounderVerdictError::MissingMaterial(
            "recognized current Verification conclusion",
        )
    })?;
    let verification_payload = verification
        .canonical_payload
        .clone()
        .filter(guided_verdict_content_address_is_complete)
        .ok_or(ClientGuidedFounderVerdictError::MissingMaterial(
            "sealed Verification canonical payload",
        ))?;
    let acceptance_contract_ref = task
        .acceptance_contract_ref
        .clone()
        .filter(guided_verdict_contract_is_complete)
        .ok_or(ClientGuidedFounderVerdictError::MissingMaterial(
            "complete frozen AcceptanceContract reference",
        ))?;
    let current_scope = VerdictScope {
        task_id: task.task_id.clone(),
        task_revision: task.revision,
        work_revision: task.work_revision,
        artifact_set_id,
        artifact_set_manifest: Some(artifact_set_manifest),
        verification_artifact_id: verification.verification_artifact_id.clone(),
        verification_payload: Some(verification_payload),
        acceptance_contract_ref: Some(acceptance_contract_ref),
    };
    let material_terms = build_guided_founder_material_terms(
        input.selection,
        conclusion,
        &input.reason_code,
        verification,
        artifact_set
            .lineage
            .as_ref()
            .expect("trusted ArtifactSet lineage"),
        &current_scope,
        confirmed_materials,
    )?;

    let supplied_digest = input.metadata.request_digest_sha256.clone();
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(input.metadata),
                scope: Some(current_scope),
                decision: material_terms.decision as i32,
                observed_verification_conclusion: conclusion as i32,
                risk_acceptances: material_terms.risk_acceptances,
                rework_directive: material_terms.rework_directive,
                reason_code: input.reason_code,
                rationale_artifact_id: None,
                required_confirmation_class: material_terms.confirmation_class as i32,
                confirmation_proof_ref: input.confirmation_proof_ref,
                expires_at: Some(input.expires_at),
                supersedes_founder_verdict_id: None,
            },
        )),
    };
    set_verdict_digest(&mut command);
    let sealed_digest = match command.command.as_ref() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => issue
            .metadata
            .as_ref()
            .expect("guided verdict metadata was supplied")
            .request_digest_sha256
            .as_str(),
        _ => unreachable!("guided verdict builder always emits an issue command"),
    };
    if !supplied_digest.is_empty() && supplied_digest != sealed_digest {
        return Err(ClientGuidedFounderVerdictError::RequestDigestMismatch);
    }
    Ok(command)
}

struct GuidedFounderMaterialTerms {
    decision: FounderVerdictDecision,
    risk_acceptances: Vec<RiskAcceptance>,
    rework_directive: Option<ReworkDirective>,
    confirmation_class: ConfirmationClass,
}

#[derive(Default)]
struct GuidedRiskMaterialGroup {
    rationale_artifact_id: Option<String>,
    compensating_control_artifact_ids: Vec<String>,
}

fn build_guided_founder_material_terms(
    selection: GuidedFounderVerdictSelection,
    conclusion: VerificationConclusion,
    reason_code: &str,
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
    current_lineage: &LineageBinding,
    current_scope: &VerdictScope,
    confirmed: Option<(&str, &FounderSupportingMaterialCollection)>,
) -> Result<GuidedFounderMaterialTerms, ClientGuidedFounderVerdictError> {
    let materials = confirmed.map(|(_, materials)| materials);
    let has_materials = materials.is_some_and(|materials| !materials.is_empty());
    match selection {
        GuidedFounderVerdictSelection::Accept if conclusion == VerificationConclusion::Passed => {
            if has_materials {
                return Err(ClientGuidedFounderVerdictError::InvalidInput(
                    "Passed Accept does not consume risk supporting materials",
                ));
            }
            Ok(GuidedFounderMaterialTerms {
                decision: FounderVerdictDecision::Accept,
                risk_acceptances: Vec::new(),
                rework_directive: None,
                confirmation_class: ConfirmationClass::Explicit,
            })
        }
        GuidedFounderVerdictSelection::Accept => {
            let Some((founder_principal_id, materials)) =
                confirmed.filter(|(_, value)| !value.is_empty())
            else {
                return Err(
                    ClientGuidedFounderVerdictError::NonPassedAcceptRequiresRiskMaterials {
                        conclusion,
                    },
                );
            };
            let risk_acceptances = build_guided_risk_acceptances(
                materials,
                founder_principal_id,
                verification,
                current_lineage,
                current_scope,
            )?;
            Ok(GuidedFounderMaterialTerms {
                decision: FounderVerdictDecision::Accept,
                risk_acceptances,
                rework_directive: None,
                confirmation_class: ConfirmationClass::ElevatedRiskAcceptance,
            })
        }
        GuidedFounderVerdictSelection::Rework => {
            if reason_code.trim().is_empty() {
                return Err(ClientGuidedFounderVerdictError::InvalidInput(
                    "Rework requires a non-empty reason_code",
                ));
            }
            let Some((founder_principal_id, materials)) =
                confirmed.filter(|(_, value)| !value.is_empty())
            else {
                return Err(ClientGuidedFounderVerdictError::ReworkRequiresDirectiveMaterials);
            };
            let rework_directive = build_guided_rework_directive(
                materials,
                founder_principal_id,
                verification,
                current_lineage,
                current_scope,
                reason_code,
            )?;
            Ok(GuidedFounderMaterialTerms {
                decision: FounderVerdictDecision::Rework,
                risk_acceptances: Vec::new(),
                rework_directive: Some(rework_directive),
                confirmation_class: ConfirmationClass::Explicit,
            })
        }
        GuidedFounderVerdictSelection::Reject => {
            if reason_code.trim().is_empty() {
                return Err(ClientGuidedFounderVerdictError::InvalidInput(
                    "Reject requires a non-empty reason_code",
                ));
            }
            if has_materials {
                return Err(ClientGuidedFounderVerdictError::InvalidInput(
                    "Reject does not consume supporting materials",
                ));
            }
            Ok(GuidedFounderMaterialTerms {
                decision: FounderVerdictDecision::Reject,
                risk_acceptances: Vec::new(),
                rework_directive: None,
                confirmation_class: ConfirmationClass::Explicit,
            })
        }
    }
}

fn build_guided_rework_directive(
    materials: &FounderSupportingMaterialCollection,
    founder_principal_id: &str,
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
    current_lineage: &LineageBinding,
    current_scope: &VerdictScope,
    reason_code: &str,
) -> Result<ReworkDirective, ClientGuidedFounderVerdictError> {
    if materials.materials.len() != 1 {
        return Err(ClientGuidedFounderVerdictError::ReworkRequiresDirectiveMaterials);
    }
    let material = &materials.materials[0];
    validate_confirmed_material_binding(
        material,
        founder_principal_id,
        verification,
        current_lineage,
        current_scope,
    )?;
    if material.capsule.role != FounderSupportingMaterialRole::ReworkRequiredChanges {
        return Err(ClientGuidedFounderVerdictError::ReworkRequiresDirectiveMaterials);
    }
    let coverage = material
        .capsule
        .coverage
        .as_ref()
        .expect("confirmed supporting material has validated coverage");
    Ok(ReworkDirective {
        directive_id: derived_founder_material_identity(
            "rework-directive",
            coverage,
            &[material.receipt.artifact_id.as_str()],
        ),
        reason_code: reason_code.to_owned(),
        required_changes_artifact_id: material.receipt.artifact_id.clone(),
        target_discrepancy_ids: coverage.discrepancy_ids.clone(),
        target_unverified_item_ids: coverage.unverified_item_ids.clone(),
    })
}

fn build_guided_risk_acceptances(
    materials: &FounderSupportingMaterialCollection,
    founder_principal_id: &str,
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
    current_lineage: &LineageBinding,
    current_scope: &VerdictScope,
) -> Result<Vec<RiskAcceptance>, ClientGuidedFounderVerdictError> {
    let mut groups: BTreeMap<(i32, Vec<String>, Vec<String>), GuidedRiskMaterialGroup> =
        BTreeMap::new();
    for material in &materials.materials {
        validate_confirmed_material_binding(
            material,
            founder_principal_id,
            verification,
            current_lineage,
            current_scope,
        )?;
        let coverage = material
            .capsule
            .coverage
            .as_ref()
            .expect("confirmed supporting material has validated coverage");
        let key = (
            coverage.risk_category,
            coverage.discrepancy_ids.clone(),
            coverage.unverified_item_ids.clone(),
        );
        let group = groups.entry(key).or_default();
        match material.capsule.role {
            FounderSupportingMaterialRole::RiskRationale
                if group.rationale_artifact_id.is_none() =>
            {
                group.rationale_artifact_id = Some(material.receipt.artifact_id.clone());
            }
            FounderSupportingMaterialRole::CompensatingControl => group
                .compensating_control_artifact_ids
                .push(material.receipt.artifact_id.clone()),
            _ => {
                return Err(ClientGuidedFounderVerdictError::MissingMaterial(
                    "each risk coverage requires one rationale and one or more compensating controls",
                ));
            }
        }
    }

    let expected_discrepancies = current_discrepancy_ids(verification)?;
    let expected_unverified = current_unverified_item_ids(verification)?;
    let mut covered_discrepancies = BTreeSet::new();
    let mut covered_unverified = BTreeSet::new();
    let mut risks = Vec::with_capacity(groups.len());
    for ((category, discrepancy_ids, unverified_item_ids), mut group) in groups {
        let Some(rationale_artifact_id) = group.rationale_artifact_id else {
            return Err(ClientGuidedFounderVerdictError::MissingMaterial(
                "each risk coverage requires one rationale and one or more compensating controls",
            ));
        };
        if group.compensating_control_artifact_ids.is_empty()
            || discrepancy_ids
                .iter()
                .any(|id| !covered_discrepancies.insert(id.clone()))
            || unverified_item_ids
                .iter()
                .any(|id| !covered_unverified.insert(id.clone()))
        {
            return Err(ClientGuidedFounderVerdictError::MissingMaterial(
                "risk supporting materials must cover each current discrepancy and unverified item exactly once",
            ));
        }
        group.compensating_control_artifact_ids.sort();
        let coverage = FounderSupportingMaterialCoverage {
            risk_category: category,
            discrepancy_ids: discrepancy_ids.clone(),
            unverified_item_ids: unverified_item_ids.clone(),
        };
        let mut identity_artifacts = vec![rationale_artifact_id.as_str()];
        identity_artifacts.extend(
            group
                .compensating_control_artifact_ids
                .iter()
                .map(String::as_str),
        );
        risks.push(RiskAcceptance {
            risk_acceptance_id: derived_founder_material_identity(
                "risk-acceptance",
                &coverage,
                &identity_artifacts,
            ),
            category,
            discrepancy_ids,
            unverified_item_ids,
            rationale_artifact_id,
            compensating_control_artifact_ids: group.compensating_control_artifact_ids,
            review_trigger_code: None,
        });
    }
    if risks.is_empty()
        || covered_discrepancies != expected_discrepancies
        || covered_unverified != expected_unverified
    {
        return Err(ClientGuidedFounderVerdictError::MissingMaterial(
            "risk supporting materials must cover each current discrepancy and unverified item exactly once",
        ));
    }
    Ok(risks)
}

fn validate_confirmed_material_binding(
    material: &ConfirmedFounderSupportingMaterialReceipt,
    founder_principal_id: &str,
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
    current_lineage: &LineageBinding,
    current_scope: &VerdictScope,
) -> Result<(), ClientGuidedFounderVerdictError> {
    let capsule = &material.capsule;
    let coverage =
        capsule
            .coverage
            .as_ref()
            .ok_or(ClientGuidedFounderVerdictError::MissingMaterial(
                "confirmed supporting material coverage",
            ))?;
    if capsule.authenticated_founder_principal_id != founder_principal_id
        || &capsule.review_lineage != current_lineage
        || &capsule.verdict_scope != current_scope
        || material.receipt.scope.as_ref() != Some(current_scope)
        || material.command.scope.as_ref() != Some(current_scope)
        || material.receipt.material_id != capsule.material_id
        || material.receipt.artifact_id
            != founder_supporting_material_artifact_id(&capsule.material_id)
        || material.receipt.role != capsule.role as i32
        || material.command.role != capsule.role as i32
        || material.command.coverage.as_ref() != Some(coverage)
        || material.receipt.canonical_payload.as_ref() != Some(&capsule.expected_payload_address)
        || !coverage_ids_belong_to_verification(coverage, verification)?
    {
        return Err(ClientGuidedFounderVerdictError::BindingChanged);
    }
    Ok(())
}

fn current_discrepancy_ids(
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
) -> Result<BTreeSet<String>, ClientGuidedFounderVerdictError> {
    unique_current_verification_ids(
        verification
            .discrepancies
            .iter()
            .map(|item| item.discrepancy_id.as_str()),
    )
}

fn current_unverified_item_ids(
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
) -> Result<BTreeSet<String>, ClientGuidedFounderVerdictError> {
    unique_current_verification_ids(
        verification
            .unverified_items
            .iter()
            .map(|item| item.unverified_item_id.as_str()),
    )
}

fn unique_current_verification_ids<'a>(
    ids: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<String>, ClientGuidedFounderVerdictError> {
    let mut unique = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() || !unique.insert(id.to_owned()) {
            return Err(ClientGuidedFounderVerdictError::Review(
                ClientTaskResultReviewError::Integrity {
                    stage: TaskResultReviewStage::Task,
                    detail: "Verification coverage identity is invalid",
                },
            ));
        }
    }
    Ok(unique)
}

fn coverage_ids_belong_to_verification(
    coverage: &FounderSupportingMaterialCoverage,
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
) -> Result<bool, ClientGuidedFounderVerdictError> {
    let discrepancies = current_discrepancy_ids(verification)?;
    let unverified = current_unverified_item_ids(verification)?;
    Ok(coverage
        .discrepancy_ids
        .iter()
        .all(|id| discrepancies.contains(id))
        && coverage
            .unverified_item_ids
            .iter()
            .all(|id| unverified.contains(id)))
}

fn derived_founder_material_identity(
    domain: &str,
    coverage: &FounderSupportingMaterialCoverage,
    artifact_ids: &[&str],
) -> String {
    let mut framed = Vec::new();
    framed.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    framed.extend_from_slice(domain.as_bytes());
    framed.extend_from_slice(&coverage.risk_category.to_be_bytes());
    for field in coverage
        .discrepancy_ids
        .iter()
        .map(String::as_str)
        .chain(coverage.unverified_item_ids.iter().map(String::as_str))
        .chain(artifact_ids.iter().copied())
    {
        framed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        framed.extend_from_slice(field.as_bytes());
    }
    format!("{domain}-{}", hex::encode(Sha256::digest(framed)))
}

struct GuidedFounderVerdictSubmission<'a> {
    command: VerdictCommand,
    selection: GuidedFounderVerdictSelection,
    materials: Option<&'a FounderSupportingMaterialCollection>,
    recovery_path: Option<&'a std::path::Path>,
}

#[cfg(test)]
async fn submit_guided_founder_verdict_via<T, TFut, E, EFut, Send, SendFuture>(
    kernel: &ClientKernel,
    command: VerdictCommand,
    selection: GuidedFounderVerdictSelection,
    now: SystemTime,
    get_task: T,
    get_evidence: E,
    send: Send,
) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError>
where
    T: FnOnce(GetTaskViewRequest) -> TFut,
    TFut: Future<Output = Result<GetTaskViewResponse, String>>,
    E: FnOnce(GetEvidenceGraphRequest) -> EFut,
    EFut: Future<Output = Result<GetEvidenceGraphResponse, String>>,
    Send: FnOnce(ExecuteFounderVerdictRequest) -> SendFuture,
    SendFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
{
    submit_guided_founder_verdict_materials_via(
        kernel,
        GuidedFounderVerdictSubmission {
            command,
            selection,
            materials: None,
            recovery_path: None,
        },
        now,
        get_task,
        get_evidence,
        send,
    )
    .await
}

async fn submit_guided_founder_verdict_materials_via<T, TFut, E, EFut, Send, SendFuture>(
    kernel: &ClientKernel,
    submission: GuidedFounderVerdictSubmission<'_>,
    now: SystemTime,
    get_task: T,
    get_evidence: E,
    send: Send,
) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError>
where
    T: FnOnce(GetTaskViewRequest) -> TFut,
    TFut: Future<Output = Result<GetTaskViewResponse, String>>,
    E: FnOnce(GetEvidenceGraphRequest) -> EFut,
    EFut: Future<Output = Result<GetEvidenceGraphResponse, String>>,
    Send: FnOnce(ExecuteFounderVerdictRequest) -> SendFuture,
    SendFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
{
    let GuidedFounderVerdictSubmission {
        command,
        selection,
        materials,
        recovery_path,
    } = submission;
    let input = guided_founder_verdict_input_from_command(&command, selection)?;
    let (authenticated_principal_id, session_id) =
        authorize_guided_founder_verdict_submission(kernel)?;
    let review =
        read_task_result_review_via(kernel, &input.current_task_id, now, get_task, get_evidence)
            .await?;
    let rebuilt = match materials {
        Some(materials) => build_guided_founder_verdict_with_materials(
            &review,
            input,
            kernel.session().ok_or(KernelError::SessionUnavailable)?,
            materials,
        )?,
        None => build_guided_founder_verdict(&review, input)?,
    };
    if rebuilt != command {
        return Err(ClientGuidedFounderVerdictError::BindingChanged);
    }
    let recovery = RecoverableGuidedFounderVerdict {
        authenticated_principal_id,
        session_id,
        selection,
        command,
    };
    if let Some(path) = recovery_path {
        let saved = DurableFounderVerdictRecovery::capture(kernel, &recovery).map_err(|_| {
            ClientGuidedFounderVerdictError::InvalidInput("invalid recovery capsule")
        })?;
        saved
            .write_new(path)
            .map_err(|_| ClientGuidedFounderVerdictError::RecoveryStorage)?;
    }
    dispatch_guided_founder_verdict(kernel, recovery, now, send).await
}

async fn retry_guided_founder_verdict_via<Send, SendFuture>(
    kernel: &ClientKernel,
    recovery: &RecoverableGuidedFounderVerdict,
    now: SystemTime,
    send: Send,
) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError>
where
    Send: FnOnce(ExecuteFounderVerdictRequest) -> SendFuture,
    SendFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_FOUNDER_VERDICT_RPC,
        ISSUE_FOUNDER_VERDICT_COMMAND,
        &session.granted_permission_codes,
    )?;
    if session.authenticated_principal_id != recovery.authenticated_principal_id
        || session.session_id != recovery.session_id
    {
        return Err(ClientGuidedFounderVerdictError::SessionChanged);
    }
    validate_sealed_guided_founder_verdict(&recovery.command, recovery.selection)?;
    // A retry-time rejection can precede Authority idempotency lookup (for
    // example, when the current principal lost permission). It therefore
    // cannot prove that the earlier transport-unknown submission did not
    // commit; retain the exact caller-owned recovery capsule.
    match dispatch_guided_founder_verdict(kernel, recovery.clone(), now, send).await {
        Err(ClientGuidedFounderVerdictError::Authority { .. }) => Ok(
            GuidedFounderVerdictAttempt::OutcomeUnknown(Box::new(recovery.clone())),
        ),
        result => result,
    }
}

fn authorize_guided_founder_verdict_submission(
    kernel: &ClientKernel,
) -> Result<(String, String), ClientGuidedFounderVerdictError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    for rpc in [GET_TASK_VIEW_RPC, GET_EVIDENCE_GRAPH_RPC] {
        kernel
            .profiles()
            .authorize_rpc(rpc, &session.granted_permission_codes)?;
    }
    kernel.profiles().authorize_command(
        EXECUTE_FOUNDER_VERDICT_RPC,
        ISSUE_FOUNDER_VERDICT_COMMAND,
        &session.granted_permission_codes,
    )?;
    Ok((
        session.authenticated_principal_id.clone(),
        session.session_id.clone(),
    ))
}

fn authorize_guided_founder_decision_submission(
    kernel: &ClientKernel,
) -> Result<(String, String), ClientGuidedFounderVerdictError> {
    let identity = authorize_guided_founder_verdict_submission(kernel)?;
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_TASK_COMMAND_RPC,
        APPLY_FOUNDER_VERDICT_COMMAND,
        &session.granted_permission_codes,
    )?;
    Ok(identity)
}

fn guided_founder_verdict_input_from_command(
    command: &VerdictCommand,
    selection: GuidedFounderVerdictSelection,
) -> Result<GuidedFounderVerdictInput, ClientGuidedFounderVerdictError> {
    let issue = match command.command.as_ref() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => issue,
        _ => {
            return Err(ClientGuidedFounderVerdictError::InvalidInput(
                "sealed command must issue a Founder Verdict",
            ));
        }
    };
    let scope = issue
        .scope
        .as_ref()
        .ok_or(ClientGuidedFounderVerdictError::InvalidInput(
            "sealed Founder Verdict scope is missing",
        ))?;
    let metadata = issue
        .metadata
        .clone()
        .ok_or(ClientGuidedFounderVerdictError::InvalidInput(
            "sealed Founder Verdict metadata is missing",
        ))?;
    let expires_at = issue
        .expires_at
        .ok_or(ClientGuidedFounderVerdictError::InvalidInput(
            "sealed Founder Verdict expiry is missing",
        ))?;
    validate_sealed_guided_founder_verdict(command, selection)?;
    Ok(GuidedFounderVerdictInput {
        current_task_id: scope.task_id.clone(),
        metadata,
        selection,
        reason_code: issue.reason_code.clone(),
        confirmation_proof_ref: issue.confirmation_proof_ref.clone(),
        expires_at,
    })
}

fn validate_sealed_guided_founder_verdict(
    command: &VerdictCommand,
    selection: GuidedFounderVerdictSelection,
) -> Result<(), ClientGuidedFounderVerdictError> {
    let issue = match command.command.as_ref() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => issue,
        _ => {
            return Err(ClientGuidedFounderVerdictError::InvalidInput(
                "sealed command must issue a Founder Verdict",
            ));
        }
    };
    let metadata = issue
        .metadata
        .as_ref()
        .ok_or(ClientGuidedFounderVerdictError::InvalidInput(
            "sealed Founder Verdict metadata is missing",
        ))?;
    if !guided_verdict_digest_is_complete(&metadata.request_digest_sha256) {
        return Err(ClientGuidedFounderVerdictError::RequestDigestMismatch);
    }
    let expected_decision = match selection {
        GuidedFounderVerdictSelection::Accept => FounderVerdictDecision::Accept,
        GuidedFounderVerdictSelection::Reject => FounderVerdictDecision::Reject,
        GuidedFounderVerdictSelection::Rework => {
            if issue.rework_directive.is_none() {
                return Err(ClientGuidedFounderVerdictError::ReworkRequiresDirectiveMaterials);
            }
            FounderVerdictDecision::Rework
        }
    };
    if issue.decision != expected_decision as i32 {
        return Err(ClientGuidedFounderVerdictError::BindingChanged);
    }
    let mut recomputed = command.clone();
    set_verdict_digest(&mut recomputed);
    if recomputed != *command {
        return Err(ClientGuidedFounderVerdictError::RequestDigestMismatch);
    }
    Ok(())
}

async fn dispatch_guided_founder_verdict<Send, SendFuture>(
    kernel: &ClientKernel,
    recovery: RecoverableGuidedFounderVerdict,
    now: SystemTime,
    send: Send,
) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError>
where
    Send: FnOnce(ExecuteFounderVerdictRequest) -> SendFuture,
    SendFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
{
    let correlation_id = guided_founder_verdict_issue(&recovery.command)?
        .metadata
        .as_ref()
        .expect("sealed guided Founder Verdict metadata")
        .correlation_id
        .clone();
    let request = ExecuteFounderVerdictRequest {
        client: Some(kernel.request_metadata(
            Uuid::now_v7().to_string(),
            Some(correlation_id),
            now,
        )?),
        command: Some(recovery.command.clone()),
    };
    let response = match send(request).await {
        Ok(response) => response,
        Err(_) => {
            return Ok(GuidedFounderVerdictAttempt::OutcomeUnknown(Box::new(
                recovery,
            )));
        }
    };
    match parse_guided_founder_verdict_response(
        response,
        &recovery.command,
        &recovery.authenticated_principal_id,
    )? {
        Some(result) => Ok(GuidedFounderVerdictAttempt::Committed(Box::new(result))),
        None => Ok(GuidedFounderVerdictAttempt::OutcomeUnknown(Box::new(
            recovery,
        ))),
    }
}

fn guided_founder_verdict_issue(
    command: &VerdictCommand,
) -> Result<&IssueFounderVerdictCommand, ClientGuidedFounderVerdictError> {
    match command.command.as_ref() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => Ok(issue),
        _ => Err(ClientGuidedFounderVerdictError::InvalidInput(
            "sealed command must issue a Founder Verdict",
        )),
    }
}

fn parse_guided_founder_verdict_response(
    response: ExecuteFounderVerdictResponse,
    expected_command: &VerdictCommand,
    expected_principal_id: &str,
) -> Result<Option<GuidedFounderVerdictResult>, ClientGuidedFounderVerdictError> {
    let ExecuteFounderVerdictResponse {
        authority_result,
        await_token,
        gateway_error,
    } = response;
    let Some(authority) = authority_result else {
        return Ok(None);
    };
    let Ok(error_code) = VerdictErrorCode::try_from(authority.error_code) else {
        return Ok(None);
    };
    if error_code != VerdictErrorCode::Unspecified {
        if authority.committed
            || authority.verdict.is_some()
            || authority.state.is_some()
            || authority.consumption_receipt.is_some()
            || authority.event.is_some()
        {
            return Ok(None);
        }
        return Err(ClientGuidedFounderVerdictError::Authority {
            error_code: authority.error_code,
            safe_error_fingerprint: authority.safe_error_fingerprint,
        });
    }
    if !guided_founder_verdict_result_matches(&authority, expected_command, expected_principal_id) {
        return Ok(None);
    }
    let await_token =
        await_token.filter(|token| guided_founder_verdict_await_token_matches(token, &authority));
    Ok(Some(GuidedFounderVerdictResult {
        authority,
        await_token,
        projection_warning: gateway_error,
    }))
}

fn guided_founder_verdict_result_matches(
    result: &VerdictCommandResult,
    expected_command: &VerdictCommand,
    expected_principal_id: &str,
) -> bool {
    let Ok(issue) = guided_founder_verdict_issue(expected_command) else {
        return false;
    };
    let (Some(verdict), Some(state), Some(event), Some(metadata)) = (
        result.verdict.as_ref(),
        result.state.as_ref(),
        result.event.as_ref(),
        issue.metadata.as_ref(),
    ) else {
        return false;
    };
    let Some(proof) = verdict.authority_proof.as_ref() else {
        return false;
    };
    result.committed
        && result.consumption_receipt.is_none()
        && result.safe_error_fingerprint.is_none()
        && !verdict.founder_verdict_id.trim().is_empty()
        && verdict.version > 0
        && verdict.scope == issue.scope
        && verdict.decision == issue.decision
        && verdict.observed_verification_conclusion == issue.observed_verification_conclusion
        && verdict.risk_acceptances == issue.risk_acceptances
        && verdict.rework_directive == issue.rework_directive
        && verdict.reason_code == issue.reason_code
        && verdict.rationale_artifact_id == issue.rationale_artifact_id
        && verdict.expires_at == issue.expires_at
        && verdict.supersedes_founder_verdict_id == issue.supersedes_founder_verdict_id
        && proof.authenticated_founder_principal_id == expected_principal_id
        && !proof.authority_ref.trim().is_empty()
        && proof.confirmation_class == issue.required_confirmation_class
        && proof.confirmation_proof_ref == issue.confirmation_proof_ref
        && verdict
            .canonical_payload
            .as_ref()
            .is_some_and(guided_verdict_content_address_is_complete)
        && state.founder_verdict_id == verdict.founder_verdict_id
        && state.revision > 0
        && state.state == FounderVerdictStateKind::Issued as i32
        && event.founder_verdict_id == verdict.founder_verdict_id
        && event.resulting_state_revision == state.revision
        && event.kind == VerdictEventKind::Issued as i32
        && event.authenticated_principal_id == expected_principal_id
        && event.command_id == metadata.command_id
        && !event.event_id.trim().is_empty()
        && event.committed_at.is_some()
}

fn guided_founder_verdict_await_token_matches(
    token: &ProjectionAwaitToken,
    result: &VerdictCommandResult,
) -> bool {
    let (Some(source), Some(expires_at), Some(verdict), Some(state), Some(event)) = (
        token.required_source_revision.as_ref(),
        token.expires_at.as_ref(),
        result.verdict.as_ref(),
        result.state.as_ref(),
        result.event.as_ref(),
    ) else {
        return false;
    };
    !token.token.trim().is_empty()
        && guided_verdict_timestamp_is_valid(expires_at)
        && source.domain == SourceDomain::FounderVerdict as i32
        && source.aggregate_id == verdict.founder_verdict_id
        && source.revision == state.revision
        && source.last_event_id == event.event_id
}

fn build_guided_founder_apply_command(
    issue_command: &VerdictCommand,
    result: &GuidedFounderVerdictResult,
) -> Result<TaskCommand, ClientGuidedFounderVerdictError> {
    let issue = guided_founder_verdict_issue(issue_command)?;
    let metadata = issue
        .metadata
        .as_ref()
        .ok_or(ClientGuidedFounderVerdictError::BindingChanged)?;
    let verdict = result
        .authority
        .verdict
        .as_ref()
        .ok_or(ClientGuidedFounderVerdictError::BindingChanged)?;
    let event = result
        .authority
        .event
        .as_ref()
        .ok_or(ClientGuidedFounderVerdictError::BindingChanged)?;
    let scope = verdict
        .scope
        .as_ref()
        .ok_or(ClientGuidedFounderVerdictError::BindingChanged)?;
    let issued_at = event
        .committed_at
        .ok_or(ClientGuidedFounderVerdictError::BindingChanged)?;

    // The Apply identity is derived only from the sealed Issue and its exact
    // immutable Authority result. Exact Issue replay therefore reconstructs
    // byte-identical Apply metadata after a process restart.
    let mut identity = Vec::new();
    for field in [
        issue_command.encode_to_vec(),
        verdict.founder_verdict_id.as_bytes().to_vec(),
        event.event_id.as_bytes().to_vec(),
    ] {
        identity.extend_from_slice(&(field.len() as u64).to_be_bytes());
        identity.extend_from_slice(&field);
    }
    let identity = hex::encode(Sha256::digest(identity));
    let mut command = TaskCommand {
        command: Some(task_command::Command::ApplyFounderVerdict(
            ApplyFounderVerdictCommand {
                meta: Some(CommandMetadata {
                    command_id: format!("apply-founder-verdict-{identity}"),
                    idempotency_key: format!("apply-founder-verdict:{identity}"),
                    idempotency_scope: GUIDED_FOUNDER_APPLY_SCOPE.to_owned(),
                    request_digest_sha256: String::new(),
                    issued_at: Some(issued_at),
                    correlation_id: metadata.correlation_id.clone(),
                    causation_id: Some(event.event_id.clone()),
                }),
                task_id: scope.task_id.clone(),
                expected_revision: scope.task_revision,
                work_revision: scope.work_revision,
                founder_verdict_id: verdict.founder_verdict_id.clone(),
            },
        )),
    };
    set_task_digest(&mut command);
    Ok(command)
}

async fn dispatch_guided_founder_apply<Send, SendFuture>(
    kernel: &ClientKernel,
    command: TaskCommand,
    verdict: GuidedFounderVerdictResult,
    now: SystemTime,
    send: Send,
) -> Result<Option<GuidedFounderDecisionResult>, ClientGuidedFounderVerdictError>
where
    Send: FnOnce(ExecuteTaskCommandRequest) -> SendFuture,
    SendFuture: Future<Output = Result<ExecuteTaskCommandResponse, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_TASK_COMMAND_RPC,
        APPLY_FOUNDER_VERDICT_COMMAND,
        &session.granted_permission_codes,
    )?;
    let apply = match command.command.as_ref() {
        Some(task_command::Command::ApplyFounderVerdict(apply)) => apply,
        _ => unreachable!("guided Founder Apply command"),
    };
    let correlation_id = apply
        .meta
        .as_ref()
        .expect("guided Founder Apply metadata")
        .correlation_id
        .clone();
    let request = ExecuteTaskCommandRequest {
        client: Some(kernel.request_metadata(
            Uuid::now_v7().to_string(),
            Some(correlation_id),
            now,
        )?),
        command: Some(command.clone()),
    };
    let response = match send(request).await {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    parse_guided_founder_apply_response(
        response,
        &command,
        &verdict,
        &session.authenticated_principal_id,
    )
}

fn parse_guided_founder_apply_response(
    response: ExecuteTaskCommandResponse,
    expected_command: &TaskCommand,
    verdict: &GuidedFounderVerdictResult,
    expected_principal_id: &str,
) -> Result<Option<GuidedFounderDecisionResult>, ClientGuidedFounderVerdictError> {
    let ExecuteTaskCommandResponse {
        authority_result,
        await_token,
        gateway_error,
    } = response;
    let Some(authority) = authority_result else {
        return Ok(None);
    };
    if let Some(task_command_result::Outcome::Error(error)) = authority.outcome.as_ref() {
        if authority.committed_event.is_some()
            || TaskErrorCode::try_from(error.code).is_err()
            || error.code == TaskErrorCode::Unspecified as i32
        {
            return Ok(None);
        }
        return Err(ClientGuidedFounderVerdictError::TaskAuthority {
            error_code: error.code,
            safe_detail_code: error.safe_detail_code.clone(),
        });
    }
    if !guided_founder_apply_result_matches(
        &authority,
        expected_command,
        verdict,
        expected_principal_id,
    ) {
        return Ok(None);
    }
    let await_token =
        await_token.filter(|token| guided_task_await_token_matches(token, &authority));
    Ok(Some(GuidedFounderDecisionResult {
        verdict: verdict.clone(),
        task: authority,
        await_token,
        projection_warning: gateway_error,
    }))
}

fn guided_founder_apply_result_matches(
    result: &TaskCommandResult,
    expected_command: &TaskCommand,
    verdict_result: &GuidedFounderVerdictResult,
    expected_principal_id: &str,
) -> bool {
    let Some(task_command::Command::ApplyFounderVerdict(expected)) =
        expected_command.command.as_ref()
    else {
        return false;
    };
    let (Some(metadata), Some(task), Some(event), Some(verdict)) = (
        expected.meta.as_ref(),
        result.outcome.as_ref().and_then(|outcome| match outcome {
            task_command_result::Outcome::Task(task) => Some(task),
            task_command_result::Outcome::Error(_) => None,
        }),
        result.committed_event.as_ref(),
        verdict_result.authority.verdict.as_ref(),
    ) else {
        return false;
    };
    let Some(scope) = verdict.scope.as_ref() else {
        return false;
    };
    let expected_status = match FounderVerdictDecision::try_from(verdict.decision) {
        Ok(FounderVerdictDecision::Accept) => DomainTaskStatus::Completed,
        Ok(FounderVerdictDecision::Rework) => DomainTaskStatus::Rework,
        Ok(FounderVerdictDecision::Reject) => DomainTaskStatus::Rejected,
        _ => return false,
    };
    let Some(resulting_revision) = scope.task_revision.checked_add(1) else {
        return false;
    };
    task.task_id == scope.task_id
        && task.revision == resulting_revision
        && task.work_revision == scope.work_revision
        && task.status == expected_status as i32
        && task.artifact_set_id.as_deref() == Some(scope.artifact_set_id.as_str())
        && task.verification_artifact_id.as_deref() == Some(scope.verification_artifact_id.as_str())
        && task.founder_verdict_id.as_deref() == Some(verdict.founder_verdict_id.as_str())
        && task.acceptance_contract_ref == scope.acceptance_contract_ref
        && event.kind == TaskEventKind::VerdictApplied as i32
        && !event.event_id.trim().is_empty()
        && event.command_id == metadata.command_id
        && event.task_id == scope.task_id
        && event.expected_revision == scope.task_revision
        && event.resulting_revision == resulting_revision
        && event.work_revision == scope.work_revision
        && event.authenticated_principal_id == expected_principal_id
        && !event.authority_ref.trim().is_empty()
        && event.idempotency_key == metadata.idempotency_key
        && event.request_digest_sha256 == metadata.request_digest_sha256
        && event.correlation_id == metadata.correlation_id
        && event.causation_id == metadata.causation_id
        && event
            .evidence_refs
            .iter()
            .any(|reference| reference == &verdict.founder_verdict_id)
        && event
            .occurred_at
            .is_some_and(|value| guided_verdict_timestamp_is_valid(&value))
        && event.snapshot.as_ref() == Some(task)
}

fn guided_task_await_token_matches(
    token: &ProjectionAwaitToken,
    result: &TaskCommandResult,
) -> bool {
    let (Some(source), Some(expires_at), Some(task), Some(event)) = (
        token.required_source_revision.as_ref(),
        token.expires_at.as_ref(),
        result.outcome.as_ref().and_then(|outcome| match outcome {
            task_command_result::Outcome::Task(task) => Some(task),
            task_command_result::Outcome::Error(_) => None,
        }),
        result.committed_event.as_ref(),
    ) else {
        return false;
    };
    !token.token.trim().is_empty()
        && guided_verdict_timestamp_is_valid(expires_at)
        && source.domain == SourceDomain::Task as i32
        && source.aggregate_id == task.task_id
        && source.revision == task.revision
        && source.last_event_id == event.event_id
}

fn validate_guided_verdict_metadata(
    metadata: &CommandMetadata,
) -> Result<(), ClientGuidedFounderVerdictError> {
    if metadata.command_id.trim().is_empty()
        || metadata.idempotency_key.trim().is_empty()
        || metadata.idempotency_scope.trim().is_empty()
        || metadata.correlation_id.trim().is_empty()
        || metadata
            .issued_at
            .as_ref()
            .is_none_or(|value| !guided_verdict_timestamp_is_valid(value))
        || (!metadata.request_digest_sha256.is_empty()
            && !guided_verdict_digest_is_complete(&metadata.request_digest_sha256))
    {
        return Err(ClientGuidedFounderVerdictError::InvalidInput(
            "caller-supplied command metadata is incomplete",
        ));
    }
    Ok(())
}

fn guided_verdict_timestamp_is_valid(value: &Timestamp) -> bool {
    value.seconds >= 0 && (0..1_000_000_000).contains(&value.nanos)
}

fn guided_verdict_digest_is_complete(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn guided_verdict_content_address_is_complete(
    address: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
) -> bool {
    address.algorithm == HashAlgorithm::Sha256 as i32
        && guided_verdict_digest_is_complete(&address.digest)
        && address.byte_length > 0
}

fn guided_verdict_contract_is_complete(
    reference: &egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference,
) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && guided_verdict_digest_is_complete(&reference.sha256)
}

async fn read_governed_task_baseline_via<F, Fut>(
    kernel: &ClientKernel,
    now: SystemTime,
    mut dispatch: F,
) -> Result<GovernedTaskBaseline, ClientGovernedTaskError>
where
    F: FnMut(ListTaskViewsRequest) -> Fut,
    Fut: Future<Output = Result<ListTaskViewsResponse, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(LIST_TASK_VIEWS_RPC, &session.granted_permission_codes)?;
    let metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    let mut pages = Vec::new();
    let mut page_cursor = None;
    let mut cursors = BTreeSet::new();
    let mut baseline_views = 0_usize;
    loop {
        if pages.len() >= GOVERNED_TASK_BASELINE_MAX_PAGES {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline page limit exceeded",
            ));
        }
        let response = dispatch(governed_task_baseline_wire_request(
            metadata.clone(),
            page_cursor.clone(),
        ))
        .await
        .map_err(ClientGovernedTaskError::Transport)?;
        if let Some(error) = response.error.as_ref() {
            return Err(ClientGovernedTaskError::Api(Box::new(error.clone())));
        }
        baseline_views = baseline_views
            .checked_add(response.views.len())
            .ok_or(ClientGovernedTaskError::BaselineLimitExceeded)?;
        if baseline_views > GOVERNED_TASK_BASELINE_MAX_VIEWS {
            return Err(ClientGovernedTaskError::BaselineLimitExceeded);
        }
        let next_cursor = response.next_page_cursor.clone();
        if let Some(next) = next_cursor.as_deref()
            && (next.trim().is_empty()
                || next.chars().any(char::is_control)
                || response.views.is_empty()
                || !cursors.insert(next.to_owned()))
        {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline cursor did not advance",
            ));
        }
        pages.push(response);
        let Some(next) = next_cursor else {
            break;
        };
        page_cursor = Some(next);
    }
    let (position, tasks) = compile_governed_task_baseline(pages)?;
    Ok(GovernedTaskBaseline { tasks, position })
}

async fn read_actionable_approval_queue_via<F, Fut>(
    kernel: &ClientKernel,
    now: SystemTime,
    mut dispatch: F,
) -> Result<ApprovalQueueBaseline, ClientApprovalWatchError>
where
    F: FnMut(ListHarnessApprovalViewsRequest) -> Fut,
    Fut: Future<Output = Result<ListHarnessApprovalViewsResponse, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_rpc(
        LIST_HARNESS_APPROVAL_VIEWS_RPC,
        &session.granted_permission_codes,
    )?;
    let metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    let mut pages = Vec::new();
    let mut page_cursor = None;
    let mut cursors = BTreeSet::new();
    let mut baseline_views = 0_usize;
    loop {
        if pages.len() >= APPROVAL_WATCH_BASELINE_MAX_PAGES {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline page limit exceeded",
            ));
        }
        let response = dispatch(approval_baseline_wire_request(
            metadata.clone(),
            page_cursor.clone(),
        ))
        .await
        .map_err(ClientApprovalWatchError::Transport)?;
        if let Some(error) = response.error.as_ref() {
            return Err(ClientApprovalWatchError::Api(Box::new(error.clone())));
        }
        baseline_views = baseline_views
            .checked_add(response.views.len())
            .ok_or(ClientApprovalWatchError::BaselineLimitExceeded)?;
        if baseline_views > APPROVAL_WATCH_BASELINE_MAX_VIEWS {
            return Err(ClientApprovalWatchError::BaselineLimitExceeded);
        }
        let next_cursor = response.next_page_cursor.clone();
        if let Some(next) = next_cursor.as_deref()
            && (next.is_empty() || response.views.is_empty() || !cursors.insert(next.to_owned()))
        {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline cursor did not advance",
            ));
        }
        pages.push(response);
        let Some(next) = next_cursor else {
            break;
        };
        page_cursor = Some(next);
    }
    let (position, actionable) = compile_approval_baseline(pages)?;
    Ok(ApprovalQueueBaseline {
        actionable,
        position,
    })
}

async fn decide_guided_approval_via<Get, GetFuture, Decide, DecideFuture>(
    kernel: &ClientKernel,
    input: GuidedApprovalDecisionInput,
    now: SystemTime,
    get_latest: Get,
    decide: Decide,
) -> Result<GuidedApprovalDecisionResult, ClientGuidedApprovalDecisionError>
where
    Get: FnOnce(GetHarnessApprovalViewRequest) -> GetFuture,
    GetFuture: Future<Output = Result<GetHarnessApprovalViewResponse, String>>,
    Decide: FnOnce(DecideHarnessApprovalRequest) -> DecideFuture,
    DecideFuture: Future<Output = Result<DecideHarnessApprovalResponse, String>>,
{
    if input.approval_request_id.trim().is_empty() {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "approval request id missing",
        ));
    }
    if input.reason_code.trim().is_empty() {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "reason code missing",
        ));
    }
    if input
        .confirmation_proof_ref
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "confirmation proof reference empty",
        ));
    }
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_rpc(
        GET_HARNESS_APPROVAL_VIEW_RPC,
        &session.granted_permission_codes,
    )?;
    kernel.profiles().authorize_command(
        DECIDE_HARNESS_APPROVAL_RPC,
        ISSUE_HARNESS_APPROVAL_DECISION_COMMAND,
        &session.granted_permission_codes,
    )?;

    let read_metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    let response = get_latest(GetHarnessApprovalViewRequest {
        client: Some(read_metadata),
        approval_request_id: input.approval_request_id.clone(),
        minimum_position: None,
    })
    .await
    .map_err(ClientGuidedApprovalDecisionError::Transport)?;
    let view = match response.outcome {
        Some(get_harness_approval_view_response::Outcome::View(view)) => view,
        Some(get_harness_approval_view_response::Outcome::Error(error))
            if error.code == egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode::NotFound as i32 =>
        {
            return Err(ClientGuidedApprovalDecisionError::NotFound);
        }
        Some(get_harness_approval_view_response::Outcome::Error(error)) => {
            return Err(ClientGuidedApprovalDecisionError::Api(Box::new(error)));
        }
        None => {
            return Err(ClientGuidedApprovalDecisionError::Protocol(
                "approval view outcome missing",
            ));
        }
    };
    validate_guided_approval_view(&view, &input.approval_request_id)?;
    if !is_actionable_approval(&view).map_err(|error| match error {
        ClientApprovalWatchError::Kernel(error) => ClientGuidedApprovalDecisionError::Kernel(error),
        ClientApprovalWatchError::Protocol(detail) => {
            ClientGuidedApprovalDecisionError::Protocol(detail)
        }
        _ => ClientGuidedApprovalDecisionError::Protocol("approval actionability invalid"),
    })? {
        return Err(ClientGuidedApprovalDecisionError::NonActionable);
    }

    if input.decision == GuidedApprovalDecision::AllowOnce
        && (!egopulse_domain_contracts::approval_display::valid_reviewable_approval_summary(
            view.display_summary.as_ref(),
            &view.display_summary_ref,
            &view.action_digest_sha256,
            view.kind,
        ) || input.reviewed_summary_digest_sha256.as_deref()
            != view
                .display_summary
                .as_ref()
                .map(|summary| summary.summary_digest_sha256.as_str()))
    {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "AllowOnce requires the complete current operation summary and its reviewed digest; read approval details again",
        ));
    }
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::IssueHarnessApprovalDecision(
                IssueHarnessApprovalDecisionCommand {
                    metadata: Some(CommandMetadata {
                        command_id: Uuid::now_v7().to_string(),
                        idempotency_key: guided_approval_idempotency_key(
                            &input.approval_request_id,
                        ),
                        idempotency_scope: APPROVAL_DECISION_IDEMPOTENCY_SCOPE.to_owned(),
                        request_digest_sha256: String::new(),
                        issued_at: Some(timestamp_from_system_time(now)?),
                        correlation_id: correlation_id.clone(),
                        causation_id: None,
                    }),
                    approval_request_id: view.approval_request_id,
                    expected_action_digest_sha256: view.action_digest_sha256,
                    expected_request_observation_id: view.request_observation_id,
                    expected_request_observation_sequence: view.request_observation_sequence,
                    decision: input.decision.wire_value(),
                    reason_code: input.reason_code,
                    confirmation_proof_ref: input.confirmation_proof_ref,
                    expected_request_revision: view.request_revision,
                },
            ),
        ),
    };
    set_policy_digest(&mut command);
    let policy_decision_command::Command::IssueHarnessApprovalDecision(command) =
        command.command.expect("guided approval command")
    else {
        unreachable!("guided approval constructs the issue branch")
    };
    let response = decide(DecideHarnessApprovalRequest {
        client: Some(kernel.request_metadata(
            Uuid::now_v7().to_string(),
            Some(correlation_id.clone()),
            now,
        )?),
        command: Some(command),
    })
    .await
    .map_err(ClientGuidedApprovalDecisionError::Transport)?;
    parse_guided_approval_response(response, input.decision, correlation_id)
}

fn guided_approval_idempotency_key(approval_request_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GUIDED_APPROVAL_IDEMPOTENCY_DOMAIN);
    hasher.update(approval_request_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_guided_approval_view(
    view: &HarnessApprovalView,
    expected_approval_request_id: &str,
) -> Result<(), ClientGuidedApprovalDecisionError> {
    if view.approval_request_id != expected_approval_request_id
        || !is_canonical_sha256(&view.action_digest_sha256)
        || view.request_observation_id.is_empty()
        || view.request_observation_sequence == 0
        || view.request_revision == 0
    {
        return Err(ClientGuidedApprovalDecisionError::Protocol(
            "approval view binding invalid",
        ));
    }
    let position = view
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.position.clone())
        .ok_or(ClientGuidedApprovalDecisionError::Protocol(
            "approval view position missing",
        ))?;
    SnapshotStreamTracker::default().apply_harness_approval_frame(
        &HarnessApprovalViewStreamFrame {
            kind: StreamFrameKind::Snapshot as i32,
            position: Some(position),
            snapshot: Some(view.clone()),
            reset_reason_code: None,
        },
    )?;
    Ok(())
}

#[allow(deprecated)]
fn parse_guided_approval_response(
    response: DecideHarnessApprovalResponse,
    expected_decision: GuidedApprovalDecision,
    correlation_id: String,
) -> Result<GuidedApprovalDecisionResult, ClientGuidedApprovalDecisionError> {
    if response.policy_authority_result.is_some() {
        return Err(ClientGuidedApprovalDecisionError::Protocol(
            "unsanitized authority result exposed",
        ));
    }
    let Some(authority) = response.sanitized_authority_result else {
        return match response.gateway_error {
            Some(error) => Err(ClientGuidedApprovalDecisionError::Api(Box::new(error))),
            None => Err(ClientGuidedApprovalDecisionError::Protocol(
                "sanitized approval result missing",
            )),
        };
    };
    let error_code = PolicyDecisionErrorCode::try_from(authority.error_code)
        .map_err(|_| ClientGuidedApprovalDecisionError::Protocol("authority error code unknown"))?;
    if error_code != PolicyDecisionErrorCode::Unspecified {
        return Err(ClientGuidedApprovalDecisionError::Authority {
            error_code: authority.error_code,
            safe_error_fingerprint: authority.safe_error_fingerprint,
        });
    }
    let decision = ApprovalDecision::try_from(authority.decision)
        .map_err(|_| ClientGuidedApprovalDecisionError::Protocol("authority decision unknown"))?;
    let state = HarnessApprovalDecisionStateKind::try_from(authority.state)
        .map_err(|_| ClientGuidedApprovalDecisionError::Protocol("authority state unknown"))?;
    if !authority.committed
        || authority.authority_decision_ref.is_empty()
        || decision == ApprovalDecision::Unspecified
        || authority.decision != expected_decision.wire_value()
        || state != HarnessApprovalDecisionStateKind::Issued
        || authority.state_revision == 0
    {
        return Err(ClientGuidedApprovalDecisionError::Protocol(
            "sanitized approval result invalid",
        ));
    }
    Ok(GuidedApprovalDecisionResult {
        authority,
        await_token: response.await_token,
        projection_warning: response.gateway_error,
        correlation_id,
    })
}

fn timestamp_from_system_time(
    value: SystemTime,
) -> Result<Timestamp, ClientGuidedApprovalDecisionError> {
    let duration = value.duration_since(std::time::UNIX_EPOCH).map_err(|_| {
        ClientGuidedApprovalDecisionError::Protocol("client clock before Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    })
}

fn governed_task_baseline_wire_request(
    metadata: ClientRequestMetadata,
    page_cursor: Option<String>,
) -> ListTaskViewsRequest {
    ListTaskViewsRequest {
        client: Some(metadata),
        status_filter: Vec::new(),
        page_size: GOVERNED_TASK_BASELINE_PAGE_SIZE,
        page_cursor,
        minimum_position: None,
    }
}

fn approval_baseline_wire_request(
    metadata: ClientRequestMetadata,
    page_cursor: Option<String>,
) -> ListHarnessApprovalViewsRequest {
    ListHarnessApprovalViewsRequest {
        client: Some(metadata),
        request_lifecycle_filter: Vec::new(),
        decision_state_filter: Vec::new(),
        task_ids: Vec::new(),
        actionable_only: true,
        page_size: APPROVAL_WATCH_BASELINE_PAGE_SIZE,
        page_cursor,
        minimum_position: None,
    }
}

fn approval_watch_wire_request(
    metadata: ClientRequestMetadata,
    resume_after: Option<ProjectionPosition>,
) -> WatchHarnessApprovalViewsRequest {
    WatchHarnessApprovalViewsRequest {
        client: Some(metadata),
        resume_after,
        approval_request_ids: Vec::new(),
        task_ids: Vec::new(),
        request_lifecycle_filter: Vec::new(),
        decision_state_filter: Vec::new(),
        actionable_only: false,
    }
}

fn compile_approval_baseline(
    pages: Vec<ListHarnessApprovalViewsResponse>,
) -> Result<(ProjectionPosition, BTreeMap<String, ActionableApproval>), ClientApprovalWatchError> {
    if pages.is_empty() {
        return Err(ClientApprovalWatchError::Protocol(
            "approval baseline returned no page",
        ));
    }
    let mut position: Option<ProjectionPosition> = None;
    let mut actionable = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_cursors = BTreeSet::new();
    let mut total = 0_usize;
    let page_count = pages.len();
    for (page_index, page) in pages.into_iter().enumerate() {
        if let Some(error) = page.error {
            return Err(ClientApprovalWatchError::Api(Box::new(error)));
        }
        let page_position = page
            .snapshot_position
            .ok_or(ClientApprovalWatchError::Protocol(
                "approval baseline position missing",
            ))?;
        if page_position.epoch.is_empty() {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline epoch missing",
            ));
        }
        if let Some(expected) = &position {
            if expected != &page_position {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline position changed across pages",
                ));
            }
        } else {
            position = Some(page_position.clone());
        }
        total = total
            .checked_add(page.views.len())
            .ok_or(ClientApprovalWatchError::BaselineLimitExceeded)?;
        if total > APPROVAL_WATCH_BASELINE_MAX_VIEWS {
            return Err(ClientApprovalWatchError::BaselineLimitExceeded);
        }
        if let Some(cursor) = page.next_page_cursor.as_deref() {
            if cursor.is_empty() || page.views.is_empty() || !seen_cursors.insert(cursor.to_owned())
            {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline cursor did not advance",
                ));
            }
            if page_index + 1 == page_count {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline pagination incomplete",
                ));
            }
        } else if page_index + 1 != page_count {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline contained pages after completion",
            ));
        }
        for view in page.views {
            if view.approval_request_id.is_empty()
                || !seen_ids.insert(view.approval_request_id.clone())
            {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline identity missing or duplicated",
                ));
            }
            let view_position = view
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.position.clone())
                .ok_or(ClientApprovalWatchError::Protocol(
                    "approval baseline view position missing",
                ))?;
            if view_position.epoch != page_position.epoch
                || view_position.sequence > page_position.sequence
            {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline view position is outside the page snapshot",
                ));
            }
            SnapshotStreamTracker::default().apply_harness_approval_frame(
                &HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Snapshot as i32,
                    position: Some(view_position),
                    snapshot: Some(view.clone()),
                    reset_reason_code: None,
                },
            )?;
            if is_actionable_approval(&view)? {
                actionable.insert(
                    view.approval_request_id.clone(),
                    ActionableApproval { view },
                );
            }
        }
    }
    Ok((
        position.expect("non-empty pages establish a position"),
        actionable,
    ))
}

fn compile_governed_task_baseline(
    pages: Vec<ListTaskViewsResponse>,
) -> Result<
    (
        GovernedProjectionPosition,
        BTreeMap<String, GovernedTaskState>,
    ),
    ClientGovernedTaskError,
> {
    if pages.is_empty() {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Task baseline returned no page",
        ));
    }
    let mut position: Option<ProjectionPosition> = None;
    let mut tasks = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_cursors = BTreeSet::new();
    let mut total = 0_usize;
    let page_count = pages.len();
    for (page_index, page) in pages.into_iter().enumerate() {
        if let Some(error) = page.error {
            return Err(ClientGovernedTaskError::Api(Box::new(error)));
        }
        let page_position = page
            .snapshot_position
            .ok_or(ClientGovernedTaskError::Protocol(
                "governed Task baseline position missing",
            ))?;
        validate_governed_identifier(&page_position.epoch, "projection epoch is invalid")?;
        if let Some(expected) = &position {
            if expected != &page_position {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline position changed across pages",
                ));
            }
        } else {
            position = Some(page_position.clone());
        }
        total = total
            .checked_add(page.views.len())
            .ok_or(ClientGovernedTaskError::BaselineLimitExceeded)?;
        if total > GOVERNED_TASK_BASELINE_MAX_VIEWS {
            return Err(ClientGovernedTaskError::BaselineLimitExceeded);
        }
        if let Some(cursor) = page.next_page_cursor.as_deref() {
            if cursor.trim().is_empty()
                || cursor.chars().any(char::is_control)
                || page.views.is_empty()
                || !seen_cursors.insert(cursor.to_owned())
            {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline cursor did not advance",
                ));
            }
            if page_index + 1 == page_count {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline pagination incomplete",
                ));
            }
        } else if page_index + 1 != page_count {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline contained pages after completion",
            ));
        }
        for view in page.views {
            let view_position = view
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.position.clone())
                .ok_or(ClientGovernedTaskError::Protocol(
                    "governed Task baseline view position missing",
                ))?;
            if view_position.epoch != page_position.epoch
                || view_position.sequence > page_position.sequence
            {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline view position is outside the page snapshot",
                ));
            }
            let raw_update = TaskWatchProcessor::default()
                .process(TaskViewStreamFrame {
                    kind: StreamFrameKind::Snapshot as i32,
                    position: Some(view_position),
                    snapshot: Some(view),
                    reset_reason_code: None,
                })
                .map_err(ClientGovernedTaskError::from)?;
            if raw_update.classification != TaskWatchClassification::Applied {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline view was not applied",
                ));
            }
            let state = governed_task_update_from_watch(raw_update)?.task.ok_or(
                ClientGovernedTaskError::Protocol("governed Task baseline view omitted its Task"),
            )?;
            if !seen_ids.insert(state.task_id.clone()) {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline identity is duplicated",
                ));
            }
            tasks.insert(state.task_id.clone(), state);
        }
    }
    let position = position.expect("non-empty pages establish a position");
    Ok((governed_position(&position)?, tasks))
}

fn governed_task_update_from_watch(
    update: TaskWatchUpdate,
) -> Result<GovernedTaskUpdate, ClientGovernedTaskError> {
    let position = governed_position(&update.position)?;
    let task = update
        .view
        .as_ref()
        .map(governed_task_state_from_view)
        .transpose()?;
    match update.classification {
        TaskWatchClassification::Applied if task.is_none() => {
            return Err(ClientGovernedTaskError::Protocol(
                "applied governed Task update omitted its Task",
            ));
        }
        TaskWatchClassification::Heartbeat | TaskWatchClassification::ResetRequired
            if task.is_some() =>
        {
            return Err(ClientGovernedTaskError::Protocol(
                "non-snapshot governed Task update included a Task",
            ));
        }
        _ => {}
    }
    if task.as_ref().is_some_and(|state| {
        state.projection.position.epoch != position.epoch
            || state.projection.position.sequence != position.sequence
    }) {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Task update position does not match its Task",
        ));
    }
    Ok(GovernedTaskUpdate {
        classification: update.classification,
        position,
        task,
    })
}

fn apply_governed_task_session_update(
    tasks: &mut BTreeMap<String, GovernedTaskState>,
    last_position: &mut GovernedProjectionPosition,
    update: &GovernedTaskUpdate,
) -> Result<(), ClientGovernedTaskError> {
    if update.classification == TaskWatchClassification::ResetRequired {
        return Ok(());
    }
    if update.position.epoch != last_position.epoch {
        return Err(ClientGovernedTaskError::Kernel(
            KernelError::StreamResetMissing,
        ));
    }
    if update.position.sequence < last_position.sequence {
        return Err(ClientGovernedTaskError::Kernel(
            KernelError::StreamOutOfOrder,
        ));
    }
    if update.classification == TaskWatchClassification::Applied {
        let state = update
            .task
            .as_ref()
            .ok_or(ClientGovernedTaskError::Protocol(
                "applied governed Task update omitted its Task",
            ))?;
        tasks.insert(state.task_id.clone(), state.clone());
    }
    if update.position.sequence > last_position.sequence {
        *last_position = update.position.clone();
    }
    Ok(())
}

fn governed_task_state_from_view(
    view: &TaskView,
) -> Result<GovernedTaskState, ClientGovernedTaskError> {
    let metadata = view
        .metadata
        .as_ref()
        .ok_or(ClientGovernedTaskError::Protocol(
            "governed Task projection metadata is missing",
        ))?;
    let position = metadata
        .position
        .as_ref()
        .ok_or(ClientGovernedTaskError::Protocol(
            "governed Task projection position is missing",
        ))?;
    let health = ProjectionHealth::try_from(metadata.health).map_err(|_| {
        ClientGovernedTaskError::Protocol("governed Task projection health is unknown")
    })?;
    if health == ProjectionHealth::Unspecified {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Task projection health is unspecified",
        ));
    }
    let projection = GovernedProjectionState {
        position: governed_position(position)?,
        health,
        stale: metadata.stale,
        reason: governed_projection_reason(metadata.safe_health_reason_code.as_deref()),
    };
    let task = view.task.as_ref().ok_or(ClientGovernedTaskError::Protocol(
        "governed Task snapshot is missing",
    ))?;
    validate_governed_identifier(&task.task_id, "governed Task identity is invalid")?;
    if task.revision == 0 || task.work_revision == 0 {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Task revision binding is invalid",
        ));
    }
    let status = DomainTaskStatus::try_from(task.status)
        .map_err(|_| ClientGovernedTaskError::Protocol("governed Task status is unknown"))?;
    if status == DomainTaskStatus::Unspecified {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Task status is unspecified",
        ));
    }
    let resume_status = DomainTaskStatus::try_from(task.resume_status)
        .map_err(|_| ClientGovernedTaskError::Protocol("governed Task resume status is unknown"))?;
    let resume_status = (resume_status != DomainTaskStatus::Unspecified).then_some(resume_status);
    let hold_reason = governed_hold_reason(task.hold_reason_code.as_deref());
    let current_run_id = validate_optional_governed_identifier(
        task.current_run_id.as_deref(),
        "governed Task current Run identity is invalid",
    )?;
    let run = match view.collaboration.as_ref() {
        Some(collaboration) => Some(governed_run_state(
            collaboration,
            &task.task_id,
            task.work_revision,
            current_run_id.as_deref(),
        )?),
        None => {
            if current_run_id.is_some()
                && !(metadata.stale
                    && projection.reason
                        == Some(GovernedProjectionReason::DependencyProjectionPending))
            {
                return Err(ClientGovernedTaskError::Protocol(
                    "governed Task omitted its current Run without dependency-pending state",
                ));
            }
            None
        }
    };
    validate_governed_source_revisions(metadata, task, run.as_ref())?;
    Ok(GovernedTaskState {
        task_id: task.task_id.clone(),
        revision: task.revision,
        status,
        resume_status,
        hold_reason,
        projection,
        run,
    })
}

fn governed_run_state(
    collaboration: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationSnapshot,
    task_id: &str,
    task_work_revision: u64,
    current_run_id: Option<&str>,
) -> Result<GovernedRunState, ClientGovernedTaskError> {
    let run = collaboration
        .run
        .as_ref()
        .ok_or(ClientGovernedTaskError::Protocol(
            "governed Collaboration omitted its Run",
        ))?;
    validate_governed_identifier(&run.run_id, "governed Run identity is invalid")?;
    if current_run_id != Some(run.run_id.as_str()) || run.task_id != task_id {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Run is not bound to the Task",
        ));
    }
    if run.revision == 0 || run.work_revision == 0 || run.work_revision != task_work_revision {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Run revision binding is invalid",
        ));
    }
    let status = RunStatus::try_from(run.status)
        .map_err(|_| ClientGovernedTaskError::Protocol("governed Run status is unknown"))?;
    if status == RunStatus::Unspecified {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Run status is unspecified",
        ));
    }
    let hold_reason = governed_hold_reason(run.hold_reason_code.as_deref());
    let actual_step_ids = collaboration
        .steps
        .iter()
        .map(|step| step.step_id.clone())
        .collect::<Vec<_>>();
    if run.step_ids != actual_step_ids {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Run Step order or membership is invalid",
        ));
    }
    let mut step_ids = BTreeSet::new();
    for step_id in &run.step_ids {
        validate_governed_identifier(step_id, "governed Step identity is invalid")?;
        if !step_ids.insert(step_id.clone()) {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Run contains duplicate Step identities",
            ));
        }
    }
    let mut attempt_ids = BTreeSet::new();
    for attempt in &collaboration.attempts {
        validate_governed_identifier(&attempt.attempt_id, "governed Attempt identity is invalid")?;
        if !attempt_ids.insert(attempt.attempt_id.clone()) || !step_ids.contains(&attempt.step_id) {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Attempt membership is invalid",
            ));
        }
    }
    let mut steps = Vec::with_capacity(collaboration.steps.len());
    for step in &collaboration.steps {
        if step.run_id != run.run_id || step.revision == 0 {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Step lineage or revision is invalid",
            ));
        }
        let step_status = StepStatus::try_from(step.status)
            .map_err(|_| ClientGovernedTaskError::Protocol("governed Step status is unknown"))?;
        if step_status == StepStatus::Unspecified {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Step status is unspecified",
            ));
        }
        let step_hold_reason = governed_hold_reason(step.hold_reason_code.as_deref());
        let current_attempt_id = validate_optional_governed_identifier(
            step.current_attempt_id.as_deref(),
            "governed current Attempt identity is invalid",
        )?;
        let raw_attempts = collaboration
            .attempts
            .iter()
            .filter(|attempt| attempt.step_id == step.step_id)
            .collect::<Vec<_>>();
        let actual_attempt_ids = raw_attempts
            .iter()
            .map(|attempt| attempt.attempt_id.clone())
            .collect::<Vec<_>>();
        if step.attempt_ids != actual_attempt_ids
            || current_attempt_id
                .as_ref()
                .is_some_and(|current| !step.attempt_ids.contains(current))
        {
            return Err(ClientGovernedTaskError::Protocol(
                "governed Step Attempt order or current Attempt is invalid",
            ));
        }
        let attempts = raw_attempts
            .into_iter()
            .map(|attempt| governed_attempt_state(attempt, &run.run_id, &step.step_id))
            .collect::<Result<Vec<_>, _>>()?;
        steps.push(GovernedStepState {
            step_id: step.step_id.clone(),
            revision: step.revision,
            status: step_status,
            hold_reason: step_hold_reason,
            current_attempt_id,
            attempts,
        });
    }
    Ok(GovernedRunState {
        run_id: run.run_id.clone(),
        revision: run.revision,
        status,
        work_revision: run.work_revision,
        hold_reason,
        steps,
    })
}

fn governed_attempt_state(
    attempt: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot,
    run_id: &str,
    step_id: &str,
) -> Result<GovernedAttemptState, ClientGovernedTaskError> {
    if attempt.run_id != run_id
        || attempt.step_id != step_id
        || attempt.revision == 0
        || attempt.attempt_number == 0
    {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Attempt lineage or revision is invalid",
        ));
    }
    let status = AttemptStatus::try_from(attempt.status)
        .map_err(|_| ClientGovernedTaskError::Protocol("governed Attempt status is unknown"))?;
    if status == AttemptStatus::Unspecified {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Attempt status is unspecified",
        ));
    }
    let recovery_class = RecoveryClass::try_from(attempt.recovery_class).map_err(|_| {
        ClientGovernedTaskError::Protocol("governed Attempt recovery class is unknown")
    })?;
    if recovery_class == RecoveryClass::Unspecified {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Attempt recovery class is unspecified",
        ));
    }
    let hold_reason = governed_hold_reason(attempt.hold_reason_code.as_deref());
    let checkpoint_reference_recorded = match attempt.latest_checkpoint_id.as_deref() {
        Some(value) => {
            validate_governed_identifier(value, "governed checkpoint identity is invalid")?;
            true
        }
        None => false,
    };
    Ok(GovernedAttemptState {
        attempt_id: attempt.attempt_id.clone(),
        revision: attempt.revision,
        attempt_number: attempt.attempt_number,
        status,
        recovery_class,
        hold_reason,
        last_harness_sequence: attempt.last_harness_sequence,
        checkpoint_reference_recorded,
    })
}

fn governed_projection_reason(value: Option<&str>) -> Option<GovernedProjectionReason> {
    value.map(|value| match value {
        "DEPENDENCY_PROJECTION_PENDING" => GovernedProjectionReason::DependencyProjectionPending,
        "PROJECTION_NOT_READY" => GovernedProjectionReason::ProjectionNotReady,
        "TASK_PROJECTION_INVALID" => GovernedProjectionReason::TaskProjectionInvalid,
        _ => GovernedProjectionReason::Unclassified,
    })
}

fn governed_hold_reason(value: Option<&str>) -> Option<GovernedHoldReason> {
    value.map(|value| match value {
        "CANCELLATION_OUTCOME_UNKNOWN" => GovernedHoldReason::CancellationOutcomeUnknown,
        "COMPENSATION_REQUIRED" => GovernedHoldReason::CompensationRequired,
        "MANUAL_RECOVERY_REQUIRED" => GovernedHoldReason::ManualRecoveryRequired,
        "IRREVERSIBLE_OUTCOME_UNKNOWN" => GovernedHoldReason::IrreversibleOutcomeUnknown,
        _ => GovernedHoldReason::Unclassified,
    })
}

fn validate_governed_source_revisions(
    metadata: &ProjectionMetadata,
    task: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot,
    run: Option<&GovernedRunState>,
) -> Result<(), ClientGovernedTaskError> {
    let mut domains = BTreeSet::new();
    let mut task_source = None;
    let mut collaboration_source = None;
    for source in &metadata.source_revisions {
        let domain = SourceDomain::try_from(source.domain).map_err(|_| {
            ClientGovernedTaskError::Protocol("governed projection source domain is unknown")
        })?;
        if domain == SourceDomain::Unspecified {
            return Err(ClientGovernedTaskError::Protocol(
                "governed projection source domain is unspecified",
            ));
        }
        if !domains.insert(source.domain) {
            return Err(ClientGovernedTaskError::Protocol(
                "governed projection source domain is duplicated",
            ));
        }
        validate_governed_identifier(
            &source.aggregate_id,
            "governed projection source identity is invalid",
        )?;
        if source.revision == 0 {
            return Err(ClientGovernedTaskError::Protocol(
                "governed projection source revision is zero",
            ));
        }
        match domain {
            SourceDomain::Task => task_source = Some(source),
            SourceDomain::Collaboration => collaboration_source = Some(source),
            _ => {}
        }
    }
    let task_source = task_source.ok_or(ClientGovernedTaskError::Protocol(
        "governed Task source revision is missing",
    ))?;
    if task_source.aggregate_id != task.task_id || task_source.revision != task.revision {
        return Err(ClientGovernedTaskError::Protocol(
            "governed Task source revision binding is invalid",
        ));
    }
    match (run, collaboration_source) {
        (Some(run), Some(source))
            if source.aggregate_id == run.run_id && source.revision == run.revision =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), None) => Err(ClientGovernedTaskError::Protocol(
            "governed Collaboration source revision is missing",
        )),
        (None, Some(_)) | (Some(_), Some(_)) => Err(ClientGovernedTaskError::Protocol(
            "governed Collaboration source revision binding is invalid",
        )),
    }
}

fn governed_position(
    value: &ProjectionPosition,
) -> Result<GovernedProjectionPosition, ClientGovernedTaskError> {
    validate_governed_identifier(&value.epoch, "projection epoch is invalid")?;
    Ok(GovernedProjectionPosition {
        epoch: value.epoch.clone(),
        sequence: value.sequence,
    })
}

fn validate_governed_identifier(
    value: &str,
    error: &'static str,
) -> Result<(), ClientGovernedTaskError> {
    if value.trim().is_empty()
        || value.len() > GOVERNED_TASK_MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        Err(ClientGovernedTaskError::Protocol(error))
    } else {
        Ok(())
    }
}

fn validate_optional_governed_identifier(
    value: Option<&str>,
    error: &'static str,
) -> Result<Option<String>, ClientGovernedTaskError> {
    value
        .map(|value| {
            validate_governed_identifier(value, error)?;
            Ok(value.to_owned())
        })
        .transpose()
}

fn task_watch_resume_after(
    request: TaskWatchRequest,
) -> Result<Option<ProjectionPosition>, ClientTaskWatchError> {
    if request.resume_epoch.is_some() != request.resume_sequence.is_some() {
        return Err(ClientTaskWatchError::InvalidResumePair);
    }
    Ok(request.resume_epoch.map(|epoch| ProjectionPosition {
        epoch,
        sequence: request
            .resume_sequence
            .expect("validated Task watch resume sequence"),
        projected_at: None,
    }))
}

async fn open_task_watch_via<T, F, Fut>(
    kernel: &ClientKernel,
    request: TaskWatchRequest,
    now: SystemTime,
    dispatch: F,
) -> Result<T, ClientTaskWatchError>
where
    F: FnOnce(WatchTaskViewsRequest) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(WATCH_TASK_VIEWS_RPC, &session.granted_permission_codes)?;
    let resume_after = task_watch_resume_after(request)?;
    let client = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    dispatch(WatchTaskViewsRequest {
        client: Some(client),
        resume_after,
        task_ids: Vec::new(),
        status_filter: Vec::new(),
    })
    .await
    .map_err(ClientTaskWatchError::Transport)
}

fn prepare_context_revoke_with_kernel(
    kernel: &ClientKernel,
    input: ContextRevokeInput,
) -> Result<PreparedContextRevoke, ClientContextRevokeError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_CONTEXT_MUTATION_RPC,
        REVOKE_CONTEXT_SNAPSHOT_COMMAND,
        &session.granted_permission_codes,
    )?;

    let request_digest_sha256 = ContextRevokeSemanticRequest {
        founder_principal_id: &session.authenticated_principal_id,
        snapshot_id: &input.snapshot_id,
        expected_state_revision: input.expected_state_revision,
        reason_code: &input.reason_code,
        evidence_refs: &input.evidence_refs,
        confirmation_proof_ref: &input.confirmation_proof_ref,
    }
    .digest_sha256();
    if !is_canonical_sha256(&request_digest_sha256) {
        return Err(ClientContextRevokeError::MalformedResponse(
            "prepared request digest",
        ));
    }

    Ok(PreparedContextRevoke {
        authenticated_principal_id: session.authenticated_principal_id.clone(),
        session_id: session.session_id.clone(),
        snapshot_id: input.snapshot_id,
        expected_state_revision: input.expected_state_revision,
        reason_code: input.reason_code,
        evidence_refs: input.evidence_refs,
        confirmation_proof_ref: input.confirmation_proof_ref,
        idempotency_key: input.idempotency_key,
        request_digest_sha256,
    })
}

async fn execute_context_revoke_via<F, Fut>(
    kernel: &ClientKernel,
    prepared: PreparedContextRevoke,
    supplied_digest_sha256: &str,
    now: SystemTime,
    send: F,
) -> Result<ContextRevokeReceipt, ClientContextRevokeError>
where
    F: FnOnce(ExecuteContextMutationRequest) -> Fut,
    Fut: Future<Output = Result<ExecuteContextMutationResponse, String>>,
{
    let request = build_context_revoke_request(kernel, &prepared, supplied_digest_sha256, now)?;
    let response = send(request)
        .await
        .map_err(ClientContextRevokeError::Transport)?;
    parse_context_revoke_response(response, &prepared)
}

fn build_context_revoke_request(
    kernel: &ClientKernel,
    prepared: &PreparedContextRevoke,
    supplied_digest_sha256: &str,
    now: SystemTime,
) -> Result<ExecuteContextMutationRequest, ClientContextRevokeError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_CONTEXT_MUTATION_RPC,
        REVOKE_CONTEXT_SNAPSHOT_COMMAND,
        &session.granted_permission_codes,
    )?;
    if session.session_id != prepared.session_id
        || session.authenticated_principal_id != prepared.authenticated_principal_id
    {
        return Err(ClientContextRevokeError::SessionChanged);
    }
    if !is_canonical_sha256(supplied_digest_sha256)
        || supplied_digest_sha256 != prepared.request_digest_sha256
    {
        return Err(ClientContextRevokeError::InvalidConfirmation);
    }

    let correlation_id = Uuid::now_v7().to_string();
    let client = kernel.request_metadata(
        Uuid::now_v7().to_string(),
        Some(correlation_id.clone()),
        now,
    )?;
    Ok(ExecuteContextMutationRequest {
        client: Some(client),
        command: Some(ContextMutationCommand {
            command: Some(context_mutation_command::Command::RevokeContextSnapshot(
                RevokeContextSnapshotCommand {
                    metadata: Some(CommandMetadata {
                        command_id: Uuid::now_v7().to_string(),
                        idempotency_key: prepared.idempotency_key.clone(),
                        idempotency_scope: CONTEXT_REVOKE_IDEMPOTENCY_SCOPE.to_owned(),
                        request_digest_sha256: prepared.request_digest_sha256.clone(),
                        issued_at: Some(now_timestamp()),
                        correlation_id,
                        causation_id: None,
                    }),
                    snapshot_id: prepared.snapshot_id.clone(),
                    expected_state_revision: prepared.expected_state_revision,
                    reason_code: prepared.reason_code.clone(),
                    evidence_refs: prepared.evidence_refs.clone(),
                    confirmation_proof_ref: prepared.confirmation_proof_ref.clone(),
                },
            )),
        }),
    })
}

fn parse_context_revoke_response(
    response: ExecuteContextMutationResponse,
    prepared: &PreparedContextRevoke,
) -> Result<ContextRevokeReceipt, ClientContextRevokeError> {
    let receipt = match response.outcome {
        Some(execute_context_mutation_response::Outcome::AuthorityResult(receipt)) => receipt,
        Some(execute_context_mutation_response::Outcome::Error(error)) => {
            return Err(ClientContextRevokeError::Api(Box::new(error)));
        }
        None => {
            return Err(ClientContextRevokeError::MalformedResponse(
                "outcome missing",
            ));
        }
    };
    let Some(expected_result_state_revision) = prepared.expected_state_revision.checked_add(1)
    else {
        return Err(ClientContextRevokeError::MalformedResponse(
            "state revision overflow",
        ));
    };
    let committed_at_is_valid = receipt
        .committed_at
        .as_ref()
        .is_some_and(|value| value.seconds >= 0 && (0..1_000_000_000).contains(&value.nanos));
    if receipt.snapshot_id != prepared.snapshot_id
        || receipt.snapshot_revision == 0
        || !is_canonical_sha256(&receipt.content_digest_sha256)
        || receipt.previous_state_revision != prepared.expected_state_revision
        || receipt.result_state_revision != expected_result_state_revision
        || receipt.previous_state != ContextGovernanceState::Issued as i32
        || receipt.result_state != ContextGovernanceState::Revoked as i32
        || !is_canonical_sha256(&receipt.request_digest_sha256)
        || receipt.request_digest_sha256 != prepared.request_digest_sha256
        || receipt.event_id.is_empty()
        || !committed_at_is_valid
        || !receipt.acknowledged_after_durability_barrier
    {
        return Err(ClientContextRevokeError::MalformedResponse(
            "authority receipt integrity",
        ));
    }
    Ok(receipt)
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Error)]
pub enum AttachError {
    #[error("invalid IPC instance: {0}")]
    InvalidInstance(String),
    #[error("local daemon unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("client kernel rejected the session: {0}")]
    Kernel(#[from] KernelError),
}

/// Attach to a running local daemon and complete the session handshake.
///
/// This function never starts, supervises, or restarts a daemon. Lifecycle
/// ownership remains with the application/daemon boundary.
pub async fn attach(
    instance: &str,
    surface: ClientSurface,
    client_instance_id: impl Into<String>,
) -> Result<ClientAttachment, AttachError> {
    let address = LocalIpcAddress::for_instance(instance)
        .map_err(|error| AttachError::InvalidInstance(error.to_string()))?;
    let connection = LocalApiClient::platform_default()
        .connect(address)
        .await
        .map_err(|error| AttachError::DaemonUnavailable(error.to_string()))?;
    let mut kernel = ClientKernel::new(client_instance_id, surface)?;
    let request = kernel.open_session_request(Uuid::now_v7().to_string())?;
    let response = connection
        .session_service()
        .open_session(request)
        .await
        .map_err(|error| AttachError::DaemonUnavailable(error.to_string()))?
        .into_inner();
    kernel.accept_open_session(response, SystemTime::now())?;
    Ok(ClientAttachment { connection, kernel })
}

#[must_use]
pub fn command_metadata(correlation_id: &str, scope: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: Uuid::now_v7().to_string(),
        idempotency_key: Uuid::now_v7().to_string(),
        idempotency_scope: scope.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now_timestamp()),
        correlation_id: correlation_id.to_owned(),
        causation_id: None,
    }
}

#[must_use]
pub fn canonical_task_digest(command: &TaskCommand) -> String {
    let mut canonical = command.clone();
    if let Some(metadata) = task_metadata_mut(&mut canonical) {
        clear_command_metadata(Some(metadata));
    }
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}

/// Seals any client-originated Task command with the same canonical digest
/// rule used by Task Authority. CLI, TUI and Desktop can therefore submit the
/// same governed write without maintaining separate digest implementations.
pub fn set_task_digest(command: &mut TaskCommand) {
    let digest = canonical_task_digest(command);
    if let Some(metadata) = task_metadata_mut(command) {
        metadata.request_digest_sha256 = digest;
    }
}

pub fn set_policy_digest(command: &mut PolicyDecisionCommand) {
    let mut canonical = command.clone();
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        canonical.command.as_mut()
        && let Some(metadata) = issue.metadata.as_mut()
    {
        clear_command_metadata(Some(metadata));
    }
    let digest = hex::encode(Sha256::digest(canonical.encode_to_vec()));
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        command.command.as_mut()
    {
        issue
            .metadata
            .as_mut()
            .expect("policy command metadata must be supplied")
            .request_digest_sha256 = digest;
    }
}

pub fn set_verdict_digest(command: &mut VerdictCommand) {
    let mut canonical = command.clone();
    match canonical.command.as_mut() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => {
            clear_command_metadata(issue.metadata.as_mut());
        }
        Some(verdict_command::Command::RevokeFounderVerdict(revoke)) => {
            clear_command_metadata(revoke.metadata.as_mut());
        }
        _ => {}
    }
    let digest = hex::encode(Sha256::digest(canonical.encode_to_vec()));
    match command.command.as_mut() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => {
            issue
                .metadata
                .as_mut()
                .expect("verdict command metadata must be supplied")
                .request_digest_sha256 = digest;
        }
        Some(verdict_command::Command::RevokeFounderVerdict(revoke)) => {
            revoke
                .metadata
                .as_mut()
                .expect("verdict command metadata must be supplied")
                .request_digest_sha256 = digest;
        }
        _ => {}
    }
}

pub fn timestamp_after(duration: std::time::Duration) -> Timestamp {
    let now = now_timestamp();
    Timestamp {
        seconds: now.seconds + duration.as_secs() as i64,
        nanos: now.nanos,
    }
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after Unix epoch");
    Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    }
}

fn clear_command_metadata(metadata: Option<&mut CommandMetadata>) {
    if let Some(metadata) = metadata {
        metadata.command_id.clear();
        metadata.request_digest_sha256.clear();
        metadata.issued_at = None;
        metadata.correlation_id.clear();
        metadata.causation_id = None;
    }
}

fn task_metadata_mut(command: &mut TaskCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskVerification(value) => value.meta.as_mut(),
        task_command::Command::ApplyFounderVerdict(value) => value.meta.as_mut(),
        task_command::Command::ReviseTask(value) => value.meta.as_mut(),
        task_command::Command::InterruptTask(value) => value.meta.as_mut(),
        task_command::Command::HoldTask(value) => value.meta.as_mut(),
        task_command::Command::ResumeTask(value) => value.meta.as_mut(),
        task_command::Command::RequestTaskCancellation(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskCancellationOutcome(value) => value.meta.as_mut(),
        task_command::Command::SupersedeTask(value) => value.meta.as_mut(),
        task_command::Command::ExpireTask(value) => value.meta.as_mut(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        pin::pin,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use egopulse_client_kernel::{
        api_contract_ref, authorization_contract_ref, client_kernel_contract_ref,
    };
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        AvailableAction, LocalApiErrorCode, OpenSessionResponse, ProjectionHealth,
        ProjectionPosition, SourceDomain, SourceRevision, StreamFrameKind,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{
            ArtifactDescriptor, ArtifactSet, Claim, ContentAddress, Evidence, LineageBinding,
            Provenance,
        },
        collaboration::v1::{AttemptSnapshot, CollaborationSnapshot, RunSnapshot, StepSnapshot},
        common::v1::ContractReference,
        localapi::v1::{ProjectionMetadata, RedactedField},
        task::v1::{TaskSnapshot, TaskStatus},
        verdict::v1::{
            FounderAuthorityProof, FounderVerdict, FounderVerdictState, VerdictEvent, VerdictScope,
        },
        verification::v1::{
            Discrepancy, UnverifiedItem, VerificationArtifact, VerificationBinding,
            VerificationConclusion,
        },
    };

    use super::*;

    const FIXED_CONTEXT_REVOKE_DIGEST: &str =
        "dc1242cf2e4c83e32ee5f95ef8cd6a5b3d8b2e64d8ab875d21ccfbb7604b9a35";
    const FIXED_CONTEXT_REVOKE_CANONICAL_HEX: &str = concat!(
        "1a0000000000000065676f70756c73652f636f6e746578742d7265766f6b652f7631",
        "0d00000000000000666f756e6465723a616c696365",
        "07000000000000006374783a303031",
        "08000000000000000200000000000000",
        "090000000000000077697468647261776e",
        "08000000000000000200000000000000",
        "0a0000000000000065766964656e63653a31",
        "0a0000000000000065766964656e63653a32",
        "0d0000000000000070726f6f663a6c6f63616c3a31",
    );
    const FIXED_CONTEXT_REVOKE_MUTATION_HEX: &str = concat!(
        "0aaf010a70121c6964656d706f74656e63793a636f6e746578742d7265766f6b653a31",
        "1a0e636f6e746578742d7265766f6b65",
        "2240646331323432636632653463383365333265653566393565663863643661356233",
        "64386232653634643861623837356432316363666262373630346239613335",
        "12076374783a3030311802",
        "220977697468647261776e",
        "2a0a65766964656e63653a31",
        "2a0a65766964656e63653a32",
        "320d70726f6f663a6c6f63616c3a31",
    );

    fn context_revoke_input() -> ContextRevokeInput {
        ContextRevokeInput {
            snapshot_id: "ctx:001".to_owned(),
            expected_state_revision: 2,
            reason_code: "withdrawn".to_owned(),
            evidence_refs: vec!["evidence:1".to_owned(), "evidence:2".to_owned()],
            confirmation_proof_ref: "proof:local:1".to_owned(),
            idempotency_key: "idempotency:context-revoke:1".to_owned(),
        }
    }

    fn authenticated_kernel(
        principal_id: &str,
        session_id: &str,
        permission_code: &str,
        now: SystemTime,
    ) -> ClientKernel {
        authenticated_kernel_for_surface(
            principal_id,
            session_id,
            permission_code,
            ClientSurface::Cli,
            now,
        )
    }

    fn authenticated_kernel_for_surface(
        principal_id: &str,
        session_id: &str,
        permission_code: &str,
        surface: ClientSurface,
        now: SystemTime,
    ) -> ClientKernel {
        authenticated_kernel_with_permissions(
            principal_id,
            session_id,
            &[permission_code],
            surface,
            now,
        )
    }

    fn authenticated_kernel_with_permissions(
        principal_id: &str,
        session_id: &str,
        permission_codes: &[&str],
        surface: ClientSurface,
        now: SystemTime,
    ) -> ClientKernel {
        authenticated_kernel_with_permissions_and_epoch(
            principal_id,
            session_id,
            permission_codes,
            surface,
            now,
            "epoch:context-revoke",
        )
    }

    fn authenticated_kernel_with_permissions_and_epoch(
        principal_id: &str,
        session_id: &str,
        permission_codes: &[&str],
        surface: ClientSurface,
        now: SystemTime,
        epoch: &str,
    ) -> ClientKernel {
        let expires_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock after epoch")
            + Duration::from_secs(60);
        let mut kernel =
            ClientKernel::new("client:context-revoke", surface).expect("client kernel");
        kernel
            .accept_open_session(
                OpenSessionResponse {
                    session_id: session_id.to_owned(),
                    authenticated_principal_id: principal_id.to_owned(),
                    negotiated_contract_ref: Some(api_contract_ref()),
                    granted_permission_codes: permission_codes
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    expires_at: Some(Timestamp {
                        seconds: expires_at.as_secs() as i64,
                        nanos: expires_at.subsec_nanos() as i32,
                    }),
                    current_position: Some(ProjectionPosition {
                        epoch: epoch.to_owned(),
                        sequence: 1,
                        projected_at: Some(Timestamp {
                            seconds: 1,
                            nanos: 0,
                        }),
                    }),
                    error: None,
                    client_kernel_contract_ref: Some(client_kernel_contract_ref()),
                    authorization_policy_ref: Some(authorization_contract_ref()),
                },
                now,
            )
            .expect("accepted session");
        kernel
    }

    fn guided_work_input() -> GuidedWorkInput {
        GuidedWorkInput {
            intent: "sensitive-intent-sentinel".to_owned(),
            work_type: "implementation".to_owned(),
            target_scope_ref: "project:guided".to_owned(),
            sources: vec![GuidedWorkSource {
                source_ref: "source:sensitive-sentinel".to_owned(),
                label: "label-sensitive-sentinel".to_owned(),
            }],
            memory_mode: GuidedWorkMemoryMode::Disabled,
            capability: GuidedWorkCapabilityChoice::FutureWorkDefault,
        }
    }

    fn guided_work_capability() -> WorkCapabilityView {
        let route = egopulse_domain_contracts::work_capability::seal_work_capability_route_binding(
            egopulse_domain_contracts::v01::egopulse::task::v1::WorkCapabilityRouteBinding {
                route_id: "route:guided:test".to_owned(),
                route_generation: 1,
                provider_profile_id: "provider-profile:guided".to_owned(),
                provider_id: "provider".to_owned(),
                harness_id: "native_harness".to_owned(),
                harness_model_id: "model:guided".to_owned(),
                provider_model_id: "model:provider".to_owned(),
                capability_profile_ref: Some(
                    egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                        contract_id: "egopulse.harness.capability.generic".to_owned(),
                        version: "1.0.0".to_owned(),
                        sha256: "d".repeat(64),
                    },
                ),
                catalog_snapshot_sha256: Some("e".repeat(64)),
                native_composition_generation: "native:test".to_owned(),
                route_binding_sha256: String::new(),
            },
        )
        .expect("sealed test work capability route");
        WorkCapabilityView {
            provider_profile_id: route.provider_profile_id.clone(),
            provider_alias: route.provider_id.clone(),
            harness_alias: route.harness_id.clone(),
            harness_model_alias: route.harness_model_id.clone(),
            provider_model_alias: route.provider_model_id.clone(),
            availability: WorkCapabilityAvailability::Admitted as i32,
            selectable: true,
            safe_reason_code: None,
            choice_id: Some("capability:guided:test".to_owned()),
            admitted_route: Some(route),
            current_future_work_default: true,
        }
    }

    fn guided_work_preview(blocked: bool) -> WorkPreparationPreview {
        let excluded_sources = blocked
            .then(
                || egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkGateNotice {
                    code: "CONTEXT_SOURCE_UNREADABLE".to_owned(),
                    detail: "source:sensitive-sentinel".to_owned(),
                    source_ref: "source:sensitive-sentinel".to_owned(),
                },
            )
            .into_iter()
            .collect::<Vec<_>>();
        WorkPreparationPreview {
            snapshot_id: format!("ctx:{}", "1".repeat(64)),
            snapshot_revision: 1,
            context_state_revision: 1,
            normalized_intent: "sensitive-intent-sentinel".to_owned(),
            work_type: "implementation".to_owned(),
            target_scope_ref: "project:guided".to_owned(),
            compiled_context_sha256: "a".repeat(64),
            confirmation_binding_sha256: "b".repeat(64),
            included_sources: vec![
                egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkSourceFact {
                    source_ref: "source:sensitive-sentinel".to_owned(),
                    label: "label-sensitive-sentinel".to_owned(),
                    authority: "project".to_owned(),
                    content_sha256: "c".repeat(64),
                    included: true,
                },
            ],
            excluded_sources: excluded_sources.clone(),
            blockers: excluded_sources,
            non_goals: vec![
                "provider/model route cannot be selected or changed by model output".to_owned(),
                "memory is not mutated by preparation".to_owned(),
            ],
            work_capability: Some(guided_work_capability()),
            work_capability_selection_source: WorkCapabilitySelectionSource::FutureWorkDefault
                as i32,
            preference_revision_at_resolution: Some(1),
            gate_ready: !blocked,
            ready_for_founder_confirmation: !blocked,
            ..WorkPreparationPreview::default()
        }
    }

    fn guided_prepare_response(blocked: bool) -> PrepareWorkResponse {
        PrepareWorkResponse {
            outcome: Some(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Preview(
                    guided_work_preview(blocked),
                ),
            ),
        }
    }

    fn guided_confirm_response(replayed: bool) -> ConfirmWorkResponse {
        ConfirmWorkResponse {
            outcome: Some(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Accepted(
                    egopulse_domain_contracts::v01::egopulse::localapi::v1::ConfirmWorkAccepted {
                        authority_result: Some(
                            egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult {
                                replayed,
                                outcome: Some(task_command_result::Outcome::Task(
                                    egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                                        task_id: "task:guided:1".to_owned(),
                                        revision: 1,
                                        work_revision: 1,
                                        status: DomainTaskStatus::Ready as i32,
                                        work_type: "implementation".to_owned(),
                                        input_snapshot_id: format!("ctx:{}", "1".repeat(64)),
                                        target_scope_ref: "project:guided".to_owned(),
                                        ..Default::default()
                                    },
                                )),
                                committed_event: None,
                            },
                        ),
                        await_token: None,
                    },
                ),
            ),
        }
    }

    #[test]
    fn guided_work_prepared_default_remains_valid_after_default_moves() {
        for (wire_source, expected) in [
            (
                WorkCapabilitySelectionSource::FutureWorkDefault,
                GovernedWorkCapabilitySelectionSource::FutureWorkDefault,
            ),
            (
                WorkCapabilitySelectionSource::LegacyOmittedDefault,
                GovernedWorkCapabilitySelectionSource::LegacyOmittedDefault,
            ),
        ] {
            let mut preview = guided_work_preview(false);
            preview.work_capability_selection_source = wire_source as i32;
            preview
                .work_capability
                .as_mut()
                .expect("prepared capability")
                .current_future_work_default = false;
            assert_eq!(
                validated_work_capability_selection(&preview)
                    .expect("sealed prepared capability remains valid"),
                expected
            );
        }
    }

    #[test]
    fn guided_work_prepares_opaque_safe_preview_and_enforces_input_bounds_before_dispatch() {
        let now = SystemTime::now();
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided",
            "session:guided",
            &["local.work.prepare", "local.work.confirm"],
            ClientSurface::Cli,
            now,
        );
        let dispatched = Cell::new(0_u64);
        let captured = RefCell::new(None);
        let prepared = block_on_ready(prepare_guided_work_via(
            &kernel,
            guided_work_input(),
            now,
            |request| {
                dispatched.set(dispatched.get() + 1);
                captured.replace(Some(request));
                async { Ok(guided_prepare_response(false)) }
            },
        ))
        .expect("guided prepare")
        .expect_prepared();
        assert_eq!(dispatched.get(), 1);
        let request = captured.borrow();
        let request = request.as_ref().expect("captured prepare request");
        assert_eq!(request.intent, "sensitive-intent-sentinel");
        assert_eq!(request.memory_mode, WorkMemoryMode::Disabled as i32);
        assert!(request.idempotency_key.starts_with("guided-work-prepare:"));
        assert_eq!(prepared.preview().work_type(), "implementation");
        let safe_debug = format!("{:?}", prepared.preview());
        for secret in [
            "source:sensitive-sentinel",
            "label-sensitive-sentinel",
            "sensitive-detail-sentinel",
            &"b".repeat(64),
        ] {
            assert!(!safe_debug.contains(secret));
        }
        assert_eq!(
            prepared.preview().non_goals(),
            &[
                GuidedWorkNonGoal::ProviderRouteCannotBeModelSelected,
                GuidedWorkNonGoal::MemoryMutationExcluded,
            ]
        );

        let missing_context = GuidedWorkInput {
            sources: Vec::new(),
            memory_mode: GuidedWorkMemoryMode::Disabled,
            ..guided_work_input()
        };
        assert!(matches!(
            validate_guided_work_input(&missing_context),
            Err(ClientGuidedWorkError::InvalidInput(
                "add a context reference or enable memory"
            ))
        ));

        for invalid in [
            GuidedWorkInput {
                intent: "\n".to_owned(),
                ..guided_work_input()
            },
            GuidedWorkInput {
                work_type: "x".repeat(GUIDED_WORK_MAX_ROUTING_BYTES + 1),
                ..guided_work_input()
            },
            GuidedWorkInput {
                sources: vec![],
                ..guided_work_input()
            },
            GuidedWorkInput {
                sources: (0..=GUIDED_WORK_MAX_SOURCES)
                    .map(|index| GuidedWorkSource {
                        source_ref: format!("source:{index}"),
                        label: format!("source:{index}"),
                    })
                    .collect(),
                ..guided_work_input()
            },
            GuidedWorkInput {
                sources: vec![GuidedWorkSource {
                    source_ref: "source\0bad".to_owned(),
                    label: "source".to_owned(),
                }],
                ..guided_work_input()
            },
        ] {
            let calls = Cell::new(0_u64);
            let result = block_on_ready(prepare_guided_work_via(&kernel, invalid, now, |_| {
                calls.set(calls.get() + 1);
                async { Ok(guided_prepare_response(false)) }
            }));
            assert!(matches!(
                result,
                Err(ClientGuidedWorkError::InvalidInput(_))
            ));
            assert_eq!(calls.get(), 0);
        }

        let mut oversized = guided_work_preview(false);
        oversized.warnings = (0..=GUIDED_WORK_MAX_SOURCES)
            .map(
                |index| egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkGateNotice {
                    code: format!("WARNING_{index}"),
                    ..Default::default()
                },
            )
            .collect();
        assert!(matches!(
            validate_guided_work_preview(
                &oversized,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));
        let mut malformed_snapshot = guided_work_preview(false);
        malformed_snapshot.snapshot_id = "ctx:ABC".to_owned();
        assert!(matches!(
            validate_guided_work_preview(
                &malformed_snapshot,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));

        let mut unknown_non_goal = guided_work_preview(false);
        unknown_non_goal.non_goals = vec!["raw-provider-canary".to_owned()];
        assert!(matches!(
            guided_work_safe_preview(&unknown_non_goal, GuidedWorkMemoryMode::Disabled),
            Err(ClientGuidedWorkError::Protocol(
                "prepared work contains an unknown non-goal"
            ))
        ));
        for non_goals in [
            vec!["provider/model route cannot be selected or changed by model output".to_owned()],
            vec![
                "memory is not mutated by preparation".to_owned(),
                "provider/model route cannot be selected or changed by model output".to_owned(),
            ],
            vec![
                "provider/model route cannot be selected or changed by model output".to_owned(),
                "memory is not mutated by preparation".to_owned(),
                "memory is not mutated by preparation".to_owned(),
            ],
        ] {
            let mut invalid_non_goals = guided_work_preview(false);
            invalid_non_goals.non_goals = non_goals;
            assert!(matches!(
                validate_guided_work_preview(
                    &invalid_non_goals,
                    "implementation",
                    "project:guided",
                    GuidedWorkMemoryMode::Disabled,
                ),
                Err(ClientGuidedWorkError::Protocol(_))
            ));
        }
        let mut unknown_blocker = guided_work_preview(true);
        unknown_blocker.blockers[0].code = "RAW_CONTEXT_CANARY".to_owned();
        unknown_blocker.excluded_sources[0].code = "RAW_CONTEXT_CANARY".to_owned();
        assert!(matches!(
            guided_work_safe_preview(&unknown_blocker, GuidedWorkMemoryMode::Disabled),
            Err(ClientGuidedWorkError::Protocol(
                "prepared work contains an unknown blocker"
            ))
        ));
        let mut unknown_warning = guided_work_preview(false);
        unknown_warning.warnings.push(
            egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkGateNotice {
                code: "RAW_WARNING_CANARY".to_owned(),
                ..Default::default()
            },
        );
        assert!(matches!(
            guided_work_safe_preview(&unknown_warning, GuidedWorkMemoryMode::Disabled),
            Err(ClientGuidedWorkError::Protocol(
                "prepared work contains an unknown warning"
            ))
        ));

        let source_mutations: [fn(&mut WorkPreparationPreview); 5] = [
            |preview: &mut WorkPreparationPreview| {
                preview.included_sources[0].source_ref = "bad\0ref".to_owned();
            },
            |preview: &mut WorkPreparationPreview| {
                preview.included_sources[0].label = " ".to_owned();
            },
            |preview: &mut WorkPreparationPreview| {
                preview.included_sources[0].authority = "provider".to_owned();
            },
            |preview: &mut WorkPreparationPreview| {
                preview.included_sources[0].content_sha256 = "ABC".to_owned();
            },
            |preview: &mut WorkPreparationPreview| {
                preview.included_sources[0].included = false;
            },
        ];
        for mutate in source_mutations {
            let mut invalid_source = guided_work_preview(false);
            mutate(&mut invalid_source);
            assert!(matches!(
                validate_guided_work_preview(
                    &invalid_source,
                    "implementation",
                    "project:guided",
                    GuidedWorkMemoryMode::Disabled,
                ),
                Err(ClientGuidedWorkError::Protocol(_))
            ));
        }
        let mut invalid_excluded = guided_work_preview(true);
        invalid_excluded.excluded_sources[0].detail = "raw-detail-canary".to_owned();
        invalid_excluded.blockers = invalid_excluded.excluded_sources.clone();
        assert!(matches!(
            validate_guided_work_preview(
                &invalid_excluded,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));
        let mut mismatched_blocker = guided_work_preview(true);
        mismatched_blocker.blockers.clear();
        assert!(matches!(
            validate_guided_work_preview(
                &mismatched_blocker,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));
        let mut inconsistent_gate = guided_work_preview(false);
        inconsistent_gate.gate_ready = false;
        assert!(matches!(
            validate_guided_work_preview(
                &inconsistent_gate,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));
        let mut inconsistent_confirmation = guided_work_preview(false);
        inconsistent_confirmation.ready_for_founder_confirmation = false;
        assert!(matches!(
            validate_guided_work_preview(
                &inconsistent_confirmation,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));
    }

    #[test]
    fn governed_memory_guided_work_accepts_empty_matches_and_rejects_disabled_mode_warnings() {
        let now = SystemTime::now();
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-memory",
            "session:guided-memory",
            &["local.work.prepare", "local.work.confirm"],
            ClientSurface::Tui,
            now,
        );
        let mut input = guided_work_input();
        input.sources.clear();
        input.memory_mode = GuidedWorkMemoryMode::GovernedRetrieval;

        let empty_warning =
            egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkGateNotice {
                code: "MEMORY_RETRIEVAL_EMPTY".to_owned(),
                detail: "governed retrieval completed with no matching accepted records".to_owned(),
                source_ref: "project:guided".to_owned(),
            };
        let mut preview = guided_work_preview(false);
        preview.included_sources.clear();
        preview.memory_authority_revision = Some(7);
        preview.memory_pack_snapshot_sha256 = Some("d".repeat(64));
        preview.warnings = vec![empty_warning.clone()];
        let captured = RefCell::new(None);
        let prepared = block_on_ready(prepare_guided_work_via(
            &kernel,
            input,
            now,
            |request| {
                captured.replace(Some(request));
                let preview = preview.clone();
                async move {
                    Ok(PrepareWorkResponse {
                        outcome: Some(
                            egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Preview(
                                preview,
                            ),
                        ),
                    })
                }
            },
        ))
        .expect("governed Memory preparation")
        .expect_prepared();
        assert_eq!(
            captured
                .borrow()
                .as_ref()
                .expect("captured request")
                .memory_mode,
            WorkMemoryMode::GovernedRetrieval as i32
        );
        assert_eq!(
            prepared.preview().memory_mode(),
            GuidedWorkMemoryMode::GovernedRetrieval
        );
        assert_eq!(prepared.preview().memory_authority_revision(), Some(7));
        assert_eq!(
            prepared.preview().memory_pack_snapshot_sha256(),
            Some("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
        );
        assert_eq!(
            prepared.preview().warnings(),
            &[GovernedWorkNotice::MemoryRetrievalEmpty]
        );

        let mut excessive_projects = guided_work_preview(false);
        excessive_projects.memory_authority_revision = Some(7);
        excessive_projects.memory_pack_snapshot_sha256 = Some("d".repeat(64));
        excessive_projects.included_sources =
            vec![excessive_projects.included_sources[0].clone(); GUIDED_WORK_MAX_SOURCES + 1];
        excessive_projects.warnings = vec![empty_warning.clone()];
        assert!(matches!(
            validate_guided_work_preview(
                &excessive_projects,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::GovernedRetrieval,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));

        let mut excessive_memory = guided_work_preview(false);
        excessive_memory.memory_authority_revision = Some(7);
        excessive_memory.memory_pack_snapshot_sha256 = Some("d".repeat(64));
        let mut memory_source = excessive_memory.included_sources[0].clone();
        memory_source.source_ref = "memory:accepted".to_owned();
        memory_source.label = "accepted Memory".to_owned();
        memory_source.authority = "memory".to_owned();
        excessive_memory.included_sources =
            vec![memory_source; WORK_MEMORY_MAX_RESULTS as usize + 1];
        assert!(matches!(
            validate_guided_work_preview(
                &excessive_memory,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::GovernedRetrieval,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));

        let mut disabled_with_memory_warning = guided_work_preview(false);
        disabled_with_memory_warning.warnings = vec![empty_warning];
        assert!(matches!(
            validate_guided_work_preview(
                &disabled_with_memory_warning,
                "implementation",
                "project:guided",
                GuidedWorkMemoryMode::Disabled,
            ),
            Err(ClientGuidedWorkError::Protocol(_))
        ));
    }

    #[test]
    fn guided_work_blocks_confirmation_and_permission_failures_before_dispatch() {
        let now = SystemTime::now();
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided",
            "session:guided",
            &["local.work.prepare", "local.work.confirm"],
            ClientSurface::Cli,
            now,
        );
        let prepared = block_on_ready(prepare_guided_work_via(
            &kernel,
            guided_work_input(),
            now,
            |_| async { Ok(guided_prepare_response(true)) },
        ))
        .unwrap()
        .expect_prepared();
        let confirm_calls = Cell::new(0_u64);
        let result = block_on_ready(confirm_guided_work_via(&kernel, prepared, now, |_| {
            confirm_calls.set(confirm_calls.get() + 1);
            async { Ok(guided_confirm_response(false)) }
        }));
        assert!(matches!(result, Err(ClientGuidedWorkError::Blocked)));
        assert_eq!(confirm_calls.get(), 0);

        let denied = authenticated_kernel(
            "founder:guided",
            "session:guided",
            "local.work.confirm",
            now,
        );
        let prepare_calls = Cell::new(0_u64);
        let result = block_on_ready(prepare_guided_work_via(
            &denied,
            guided_work_input(),
            now,
            |_| {
                prepare_calls.set(prepare_calls.get() + 1);
                async { Ok(guided_prepare_response(false)) }
            },
        ));
        assert!(matches!(
            result,
            Err(ClientGuidedWorkError::Kernel(
                KernelError::PermissionDenied(_)
            ))
        ));
        assert_eq!(prepare_calls.get(), 0);

        let missing_confirm = authenticated_kernel(
            "founder:guided",
            "session:guided",
            "local.work.prepare",
            now,
        );
        let prepare_calls = Cell::new(0_u64);
        let result = block_on_ready(prepare_guided_work_via(
            &missing_confirm,
            guided_work_input(),
            now,
            |_| {
                prepare_calls.set(prepare_calls.get() + 1);
                async { Ok(guided_prepare_response(false)) }
            },
        ));
        assert!(matches!(
            result,
            Err(ClientGuidedWorkError::Kernel(
                KernelError::PermissionDenied(_)
            ))
        ));
        assert_eq!(prepare_calls.get(), 0);
    }

    #[test]
    fn guided_work_transport_unknown_replays_the_exact_sealed_command_once() {
        let now = SystemTime::now();
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided",
            "session:guided",
            &["local.work.prepare", "local.work.confirm"],
            ClientSurface::Cli,
            now,
        );
        let prepare_error_request = RefCell::new(None);
        let prepare_error_attempt = block_on_ready(prepare_guided_work_via(
            &kernel,
            guided_work_input(),
            now,
            |request| {
                prepare_error_request.replace(Some(request));
                async {
                    Ok(PrepareWorkResponse {
                        outcome: Some(
                            egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Error(
                                LocalApiError::default(),
                            ),
                        ),
                    })
                }
            },
        ))
        .unwrap();
        let GuidedWorkPreparationAttempt::OutcomeUnknown(prepare_error_recovery) =
            prepare_error_attempt
        else {
            panic!("prepare error response must retain the sealed request")
        };
        assert!(matches!(
            block_on_ready(replay_guided_work_preparation_via(
                &kernel,
                &prepare_error_recovery,
                |_| async {
                    Ok(PrepareWorkResponse {
                        outcome: Some(
                            egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Error(
                                LocalApiError::default(),
                            ),
                        ),
                    })
                },
            )),
            Err(ClientGuidedWorkError::ApiOutcomeUnknown(_))
        ));
        let prepare_error_replay_request = RefCell::new(None);
        let prepared_after_error = block_on_ready(replay_guided_work_preparation_via(
            &kernel,
            &prepare_error_recovery,
            |request| {
                prepare_error_replay_request.replace(Some(request));
                async { Ok(guided_prepare_response(false)) }
            },
        ))
        .unwrap();
        assert_eq!(
            prepare_error_request
                .borrow()
                .as_ref()
                .unwrap()
                .encode_to_vec(),
            prepare_error_replay_request
                .borrow()
                .as_ref()
                .unwrap()
                .encode_to_vec()
        );
        assert_eq!(
            prepared_after_error.confirm_idempotency_key,
            prepare_error_recovery.confirm_idempotency_key
        );
        let order = RefCell::new(Vec::new());
        let uncertain_prepare = RefCell::new(None);
        let preparation = block_on_ready(prepare_guided_work_via(
            &kernel,
            guided_work_input(),
            now,
            |request| {
                uncertain_prepare.replace(Some(request));
                async { Err("prepare connection closed after write".to_owned()) }
            },
        ))
        .unwrap();
        let GuidedWorkPreparationAttempt::OutcomeUnknown(preparation_recovery) = preparation else {
            panic!("prepare transport failure must retain the sealed request")
        };
        let sealed_confirm_idempotency = preparation_recovery.confirm_idempotency_key.clone();
        let replayed_prepare = RefCell::new(None);
        let replayed_prepared = block_on_ready(replay_guided_work_preparation_via(
            &kernel,
            &preparation_recovery,
            |request| {
                replayed_prepare.replace(Some(request));
                async { Ok(guided_prepare_response(false)) }
            },
        ))
        .unwrap();
        assert_eq!(
            uncertain_prepare.borrow().as_ref().unwrap().encode_to_vec(),
            replayed_prepare.borrow().as_ref().unwrap().encode_to_vec()
        );
        assert_eq!(
            replayed_prepared.prepare_idempotency_key,
            preparation_recovery.request.idempotency_key
        );
        assert_eq!(
            replayed_prepared.confirm_idempotency_key,
            sealed_confirm_idempotency
        );
        let changed_prepare_session = authenticated_kernel_with_permissions(
            "founder:guided",
            "session:other",
            &["local.work.prepare", "local.work.confirm"],
            ClientSurface::Cli,
            now,
        );
        let prepare_replay_calls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(replay_guided_work_preparation_via(
                &changed_prepare_session,
                &preparation_recovery,
                |_| {
                    prepare_replay_calls.set(prepare_replay_calls.get() + 1);
                    async { Ok(guided_prepare_response(false)) }
                },
            )),
            Err(ClientGuidedWorkError::SessionChanged)
        ));
        assert_eq!(prepare_replay_calls.get(), 0);
        assert!(matches!(
            block_on_ready(replay_guided_work_preparation_via(
                &kernel,
                &preparation_recovery,
                |_| async { Err("private prepare replay transport".to_owned()) },
            )),
            Err(ClientGuidedWorkError::PreparationOutcomeUnknown(detail))
                if detail == "private prepare replay transport"
        ));
        let prepared = replayed_prepared;
        let first_request = RefCell::new(None);
        let attempt = block_on_ready(confirm_guided_work_via(&kernel, prepared, now, |request| {
            order.borrow_mut().push("confirm");
            first_request.replace(Some(request));
            async { Err("connection closed after write".to_owned()) }
        }))
        .unwrap();
        let GuidedWorkConfirmationAttempt::OutcomeUnknown(recovery) = attempt else {
            panic!("transport failure must retain exact confirmation")
        };
        assert!(matches!(
            block_on_ready(replay_guided_work_confirmation_via(
                &kernel,
                &recovery,
                |_| async {
                    Ok(ConfirmWorkResponse {
                        outcome: Some(
                            egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Error(
                                LocalApiError::default(),
                            ),
                        ),
                    })
                },
            )),
            Err(ClientGuidedWorkError::ApiOutcomeUnknown(_))
        ));
        let replay_request = RefCell::new(None);
        let confirmed = block_on_ready(replay_guided_work_confirmation_via(
            &kernel,
            &recovery,
            |request| {
                order.borrow_mut().push("replay");
                replay_request.replace(Some(request));
                async { Ok(guided_confirm_response(true)) }
            },
        ))
        .unwrap();
        assert!(confirmed.result.replayed);
        assert_eq!(*order.borrow(), ["confirm", "replay"]);
        assert_eq!(
            first_request.borrow().as_ref().unwrap().encode_to_vec(),
            replay_request.borrow().as_ref().unwrap().encode_to_vec()
        );
        assert!(
            first_request
                .borrow()
                .as_ref()
                .unwrap()
                .idempotency_key
                .starts_with("guided-work-confirm:")
        );

        let changed_session = authenticated_kernel_with_permissions(
            "founder:guided",
            "session:other",
            &["local.work.confirm"],
            ClientSurface::Cli,
            now,
        );
        let replay_calls = Cell::new(0_u64);
        let result = block_on_ready(replay_guided_work_confirmation_via(
            &changed_session,
            &recovery,
            |_| {
                replay_calls.set(replay_calls.get() + 1);
                async { Ok(guided_confirm_response(true)) }
            },
        ));
        assert!(matches!(result, Err(ClientGuidedWorkError::SessionChanged)));
        assert_eq!(replay_calls.get(), 0);
        assert!(matches!(
            block_on_ready(replay_guided_work_confirmation_via(
                &kernel,
                &recovery,
                |_| async { Err("private confirm replay transport".to_owned()) },
            )),
            Err(ClientGuidedWorkError::ConfirmationOutcomeUnknown(detail))
                if detail == "private confirm replay transport"
        ));
    }

    #[test]
    fn guided_work_confirmation_rejects_binding_drift_and_non_task_outcomes() {
        let now = SystemTime::now();
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided",
            "session:guided",
            &["local.work.prepare", "local.work.confirm"],
            ClientSurface::Cli,
            now,
        );
        let prepared = block_on_ready(prepare_guided_work_via(
            &kernel,
            guided_work_input(),
            now,
            |_| async { Ok(guided_prepare_response(false)) },
        ))
        .unwrap()
        .expect_prepared();
        let mut recovery = seal_guided_work_confirmation(&kernel, prepared, now).unwrap();
        recovery.request.confirmation_binding_sha256 = "d".repeat(64);
        let calls = Cell::new(0_u64);
        let result = block_on_ready(replay_guided_work_confirmation_via(
            &kernel,
            &recovery,
            |_| {
                calls.set(calls.get() + 1);
                async { Ok(guided_confirm_response(false)) }
            },
        ));
        assert!(matches!(result, Err(ClientGuidedWorkError::BindingChanged)));
        assert_eq!(calls.get(), 0);

        recovery.request.confirmation_binding_sha256 = "b".repeat(64);
        let missing = ConfirmWorkResponse {
            outcome: Some(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Accepted(
                    egopulse_domain_contracts::v01::egopulse::localapi::v1::ConfirmWorkAccepted {
                        authority_result: Some(Default::default()),
                        await_token: None,
                    },
                ),
            ),
        };
        assert!(matches!(
            parse_guided_work_confirmation(missing, &recovery),
            Err(ClientGuidedWorkError::Protocol(
                "confirmed task authority outcome missing"
            ))
        ));

        let gateway_error = ConfirmWorkResponse {
            outcome: Some(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Error(
                    LocalApiError::default(),
                ),
            ),
        };
        let prepared = block_on_ready(prepare_guided_work_via(
            &kernel,
            guided_work_input(),
            now,
            |_| async { Ok(guided_prepare_response(false)) },
        ))
        .unwrap()
        .expect_prepared();
        assert!(matches!(
            block_on_ready(confirm_guided_work_via(&kernel, prepared, now, |_| async {
                Ok(gateway_error)
            },)),
            Ok(GuidedWorkConfirmationAttempt::OutcomeUnknown(_))
        ));
    }

    fn normalized_context_revoke_mutation_bytes(request: ExecuteContextMutationRequest) -> Vec<u8> {
        let mut mutation = request.command.expect("Context mutation envelope");
        let context_mutation_command::Command::RevokeContextSnapshot(command) =
            mutation.command.as_mut().expect("Context revoke command");
        let metadata = command.metadata.as_mut().expect("command metadata");
        metadata.command_id.clear();
        metadata.issued_at = None;
        metadata.correlation_id.clear();
        metadata.causation_id = None;
        mutation.encode_to_vec()
    }

    fn success_context_revoke_receipt() -> ContextRevokeReceipt {
        ContextRevokeReceipt {
            snapshot_id: "ctx:001".to_owned(),
            snapshot_revision: 1,
            content_digest_sha256: "b".repeat(64),
            previous_state_revision: 2,
            result_state_revision: 3,
            previous_state: ContextGovernanceState::Issued as i32,
            result_state: ContextGovernanceState::Revoked as i32,
            request_digest_sha256: FIXED_CONTEXT_REVOKE_DIGEST.to_owned(),
            event_id: "context-event:revoke:1".to_owned(),
            committed_at: Some(Timestamp {
                seconds: 100,
                nanos: 7,
            }),
            replayed: false,
            acknowledged_after_durability_barrier: true,
        }
    }

    fn review_position(sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: "epoch:review".to_owned(),
            sequence,
            projected_at: Some(Timestamp {
                seconds: sequence as i64,
                nanos: 0,
            }),
        }
    }

    fn review_source(domain: SourceDomain, id: &str, revision: u64) -> SourceRevision {
        SourceRevision {
            domain: domain as i32,
            aggregate_id: id.to_owned(),
            revision,
            last_event_id: format!("event:{id}:{revision}"),
        }
    }

    fn review_metadata(sequence: u64, sources: Vec<SourceRevision>) -> ProjectionMetadata {
        ProjectionMetadata {
            schema_ref: Some(ContractReference {
                contract_id: "egopulse.localapi.v1/review".to_owned(),
                version: "0.1.0".to_owned(),
                sha256: "a".repeat(64),
            }),
            position: Some(review_position(sequence)),
            source_revisions: sources,
            health: ProjectionHealth::Ready as i32,
            stale: false,
            safe_health_reason_code: None,
        }
    }

    fn review_lineage() -> LineageBinding {
        LineageBinding {
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
        }
    }

    fn review_address(seed: char) -> ContentAddress {
        ContentAddress {
            algorithm: 1,
            digest: seed.to_string().repeat(64),
            byte_length: 12,
        }
    }

    fn task_result_fixture() -> (TaskView, EvidenceGraphView) {
        let lineage = review_lineage();
        let manifest = review_address('b');
        let verification_payload = review_address('c');
        let acceptance = ContractReference {
            contract_id: "acceptance:review".to_owned(),
            version: "1".to_owned(),
            sha256: "d".repeat(64),
        };
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
                artifact_set_manifest: Some(manifest.clone()),
                claim_id: "claim:review".to_owned(),
                acceptance_contract_ref: Some(acceptance.clone()),
                ..Default::default()
            }),
            conclusion: VerificationConclusion::Passed as i32,
            canonical_payload: Some(verification_payload.clone()),
            ..Default::default()
        };
        let verdict = FounderVerdict {
            founder_verdict_id: "verdict:review".to_owned(),
            version: 1,
            decision: FounderVerdictDecision::Accept as i32,
            scope: Some(VerdictScope {
                task_id: "task:review".to_owned(),
                task_revision: 6,
                work_revision: 2,
                artifact_set_id: artifact_set.artifact_set_id.clone(),
                artifact_set_manifest: Some(manifest),
                verification_artifact_id: verification.verification_artifact_id.clone(),
                verification_payload: Some(verification_payload),
                acceptance_contract_ref: Some(acceptance.clone()),
            }),
            observed_verification_conclusion: VerificationConclusion::Passed as i32,
            ..Default::default()
        };
        let task_view = TaskView {
            metadata: Some(review_metadata(
                20,
                vec![
                    review_source(SourceDomain::Task, "task:review", 7),
                    review_source(SourceDomain::Artifact, "artifact-set:review", 3),
                    review_source(SourceDomain::Verification, "verification:review", 2),
                    review_source(SourceDomain::FounderVerdict, "verdict:review", 1),
                ],
            )),
            task: Some(TaskSnapshot {
                task_id: "task:review".to_owned(),
                revision: 7,
                work_revision: 2,
                status: TaskStatus::Active as i32,
                artifact_set_id: Some(artifact_set.artifact_set_id.clone()),
                verification_artifact_id: Some(verification.verification_artifact_id.clone()),
                founder_verdict_id: Some(verdict.founder_verdict_id.clone()),
                acceptance_contract_ref: Some(acceptance),
                ..Default::default()
            }),
            artifact_set: Some(artifact_set),
            verification: Some(verification),
            founder_verdict: Some(verdict),
            founder_verdict_state: Some(FounderVerdictState {
                founder_verdict_id: "verdict:review".to_owned(),
                revision: 1,
                state: 1,
                ..Default::default()
            }),
            redactions: vec![RedactedField {
                field_path: "founder_verdict.authority_proof".to_owned(),
                reason_code: "PRIVATE_AUTHORITY_PROOF".to_owned(),
            }],
            ..Default::default()
        };
        let graph = EvidenceGraphView {
            metadata: Some(review_metadata(
                10,
                vec![
                    review_source(SourceDomain::Artifact, "artifact-set:review", 3),
                    review_source(SourceDomain::Artifact, "artifact:review", 1),
                    review_source(SourceDomain::Artifact, "claim:review", 1),
                    review_source(SourceDomain::Artifact, "evidence:review", 1),
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
            redactions: vec![RedactedField {
                field_path: "artifacts.provenance.raw_source_ref".to_owned(),
                reason_code: "RAW_SOURCE_REDACTED".to_owned(),
            }],
        };
        (task_view, graph)
    }

    fn verdict_pending_review(conclusion: VerificationConclusion) -> TaskResultReview {
        let (mut task_view, evidence_graph) = task_result_fixture();
        let task = task_view.task.as_mut().unwrap();
        task.status = TaskStatus::VerdictPending as i32;
        task.founder_verdict_id = None;
        task_view.verification.as_mut().unwrap().conclusion = conclusion as i32;
        task_view.founder_verdict = None;
        task_view.founder_verdict_state = None;
        task_view
            .metadata
            .as_mut()
            .unwrap()
            .source_revisions
            .retain(|source| source.domain != SourceDomain::FounderVerdict as i32);
        task_view.available_actions = vec![AvailableAction {
            kind: AvailableActionKind::SubmitFounderVerdict as i32,
            owning_authority: "FounderVerdictAuthority".to_owned(),
            derivation_rule_ref: "rule:task-actionability:v1".to_owned(),
            explicit_confirmation_required: true,
            reason_code: None,
        }];
        TaskResultReview {
            task_view,
            evidence_graph: Some(evidence_graph),
        }
    }

    fn verdict_review_with_open_items(conclusion: VerificationConclusion) -> TaskResultReview {
        let mut review = verdict_pending_review(conclusion);
        let verification = review
            .task_view
            .verification
            .as_mut()
            .expect("review verification");
        verification.discrepancies = vec![Discrepancy {
            discrepancy_id: "discrepancy:review:1".to_owned(),
            criterion_id: "criterion:review".to_owned(),
            ..Default::default()
        }];
        verification.unverified_items = vec![UnverifiedItem {
            unverified_item_id: "unverified:review:1".to_owned(),
            criterion_id: "criterion:review".to_owned(),
            ..Default::default()
        }];
        review
    }

    fn guided_verdict_input(selection: GuidedFounderVerdictSelection) -> GuidedFounderVerdictInput {
        GuidedFounderVerdictInput {
            current_task_id: "task:review".to_owned(),
            metadata: CommandMetadata {
                command_id: "command:guided-verdict:1".to_owned(),
                idempotency_key: "idempotency:guided-verdict:1".to_owned(),
                idempotency_scope: "founder-verdict".to_owned(),
                request_digest_sha256: String::new(),
                issued_at: Some(Timestamp {
                    seconds: 100,
                    nanos: 0,
                }),
                correlation_id: "correlation:guided-verdict:1".to_owned(),
                causation_id: Some("review:task:review".to_owned()),
            },
            selection,
            reason_code: "founder-reviewed-result".to_owned(),
            confirmation_proof_ref: "confirmation:guided-verdict:1".to_owned(),
            expires_at: Timestamp {
                seconds: 3_700,
                nanos: 0,
            },
        }
    }

    fn sealed_guided_verdict_command(selection: GuidedFounderVerdictSelection) -> VerdictCommand {
        build_guided_founder_verdict(
            &verdict_pending_review(VerificationConclusion::Passed),
            guided_verdict_input(selection),
        )
        .expect("sealed guided Founder Verdict command")
    }

    fn prepared_founder_supporting_material(
        kernel: &ClientKernel,
    ) -> PreparedFounderSupportingMaterial {
        let review = verdict_pending_review(VerificationConclusion::Partial);
        let builder = FounderSupportingMaterialBuilder::from_review(
            &review,
            kernel.session().expect("authenticated test session"),
            "material:risk-rationale:1".to_owned(),
            FounderSupportingMaterialRole::RiskRationale,
            "Founder rationale for the reviewed residual risk.".to_owned(),
            Some(FounderSupportingMaterialCoverage {
                risk_category: RiskCategory::QualityResidual as i32,
                discrepancy_ids: vec!["discrepancy:review:1".to_owned()],
                unverified_item_ids: Vec::new(),
            }),
        )
        .expect("trusted supporting-material builder");
        builder
            .build(CommandMetadata {
                command_id: "command:founder-material:1".to_owned(),
                idempotency_key: "idempotency:founder-material:1".to_owned(),
                idempotency_scope: "founder-supporting-material/v1".to_owned(),
                request_digest_sha256: String::new(),
                issued_at: Some(Timestamp {
                    seconds: 100,
                    nanos: 0,
                }),
                correlation_id: "correlation:founder-material:1".to_owned(),
                causation_id: Some("review:task:review".to_owned()),
            })
            .expect("sealed supporting-material command")
    }

    fn founder_supporting_material_response(
        prepared: &PreparedFounderSupportingMaterial,
        replayed: bool,
    ) -> CreateFounderSupportingMaterialResponse {
        let metadata = prepared
            .command()
            .metadata
            .as_ref()
            .expect("supporting-material metadata");
        CreateFounderSupportingMaterialResponse {
            authority_result: Some(FounderSupportingMaterialReceipt {
                committed: true,
                replayed,
                material_id: prepared.command().material_id.clone(),
                artifact_id: founder_supporting_material_artifact_id(
                    &prepared.command().material_id,
                ),
                role: prepared.command().role,
                scope: prepared.command().scope.clone(),
                canonical_payload: Some(prepared.capsule().expected_payload_address.clone()),
                command_id: metadata.command_id.clone(),
                correlation_id: metadata.correlation_id.clone(),
            }),
            await_token: None,
            gateway_error: None,
        }
    }

    fn confirmed_founder_supporting_material(
        review: &TaskResultReview,
        kernel: &ClientKernel,
        material_id: &str,
        role: FounderSupportingMaterialRole,
        coverage: FounderSupportingMaterialCoverage,
    ) -> ConfirmedFounderSupportingMaterialReceipt {
        let prepared = FounderSupportingMaterialBuilder::from_review(
            review,
            kernel.session().expect("authenticated test session"),
            material_id.to_owned(),
            role,
            format!("Founder authored {material_id}"),
            Some(coverage),
        )
        .expect("trusted supporting material")
        .build(CommandMetadata {
            command_id: format!("command:{material_id}"),
            idempotency_key: format!("idempotency:{material_id}"),
            idempotency_scope: "founder-supporting-material/v1".to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(Timestamp {
                seconds: 100,
                nanos: 0,
            }),
            correlation_id: format!("correlation:{material_id}"),
            causation_id: Some("review:task:review".to_owned()),
        })
        .expect("prepared supporting material");
        let receipt = founder_supporting_material_response(&prepared, false)
            .authority_result
            .expect("confirmed supporting material receipt");
        ConfirmedFounderSupportingMaterialReceipt::from_prepared(receipt, &prepared)
            .expect("exact supporting material receipt")
    }

    fn guided_verdict_response(
        command: &VerdictCommand,
        replayed: bool,
    ) -> ExecuteFounderVerdictResponse {
        let issue = guided_founder_verdict_issue(command).expect("guided issue command");
        let metadata = issue.metadata.as_ref().expect("guided issue metadata");
        let verdict_id = "founder-verdict:guided:1".to_owned();
        let state = FounderVerdictState {
            founder_verdict_id: verdict_id.clone(),
            revision: 1,
            state: FounderVerdictStateKind::Issued as i32,
            consumption_receipt_id: None,
            superseded_by_verdict_id: None,
            terminal_reason_code: None,
            updated_at: Some(Timestamp {
                seconds: 200,
                nanos: 0,
            }),
        };
        ExecuteFounderVerdictResponse {
            authority_result: Some(VerdictCommandResult {
                committed: true,
                replayed,
                verdict: Some(FounderVerdict {
                    founder_verdict_id: verdict_id.clone(),
                    version: 1,
                    decision: issue.decision,
                    scope: issue.scope.clone(),
                    observed_verification_conclusion: issue.observed_verification_conclusion,
                    authority_proof: Some(FounderAuthorityProof {
                        authenticated_founder_principal_id: "founder:guided-verdict".to_owned(),
                        authority_ref: "authority:founder-verdict".to_owned(),
                        confirmation_class: issue.required_confirmation_class,
                        confirmation_proof_ref: issue.confirmation_proof_ref.clone(),
                        verified_at: Some(Timestamp {
                            seconds: 200,
                            nanos: 0,
                        }),
                        valid_until: issue.expires_at,
                        authority_policy_ref: Some(ContractReference {
                            contract_id: "founder-verdict-policy".to_owned(),
                            version: "v1".to_owned(),
                            sha256: "d".repeat(64),
                        }),
                    }),
                    risk_acceptances: issue.risk_acceptances.clone(),
                    rework_directive: issue.rework_directive.clone(),
                    reason_code: issue.reason_code.clone(),
                    rationale_artifact_id: issue.rationale_artifact_id.clone(),
                    valid_from: Some(Timestamp {
                        seconds: 200,
                        nanos: 0,
                    }),
                    expires_at: issue.expires_at,
                    issued_at: Some(Timestamp {
                        seconds: 200,
                        nanos: 0,
                    }),
                    canonical_payload: Some(ContentAddress {
                        algorithm: HashAlgorithm::Sha256 as i32,
                        digest: "e".repeat(64),
                        byte_length: 64,
                    }),
                    supersedes_founder_verdict_id: issue.supersedes_founder_verdict_id.clone(),
                }),
                state: Some(state.clone()),
                consumption_receipt: None,
                event: Some(VerdictEvent {
                    event_id: "verdict-event:guided:1".to_owned(),
                    kind: VerdictEventKind::Issued as i32,
                    founder_verdict_id: verdict_id,
                    resulting_state_revision: state.revision,
                    authenticated_principal_id: "founder:guided-verdict".to_owned(),
                    command_id: metadata.command_id.clone(),
                    evidence_artifact_ids: Vec::new(),
                    committed_at: Some(Timestamp {
                        seconds: 200,
                        nanos: 0,
                    }),
                }),
                error_code: VerdictErrorCode::Unspecified as i32,
                safe_error_fingerprint: None,
            }),
            await_token: None,
            gateway_error: None,
        }
    }

    fn guided_apply_response(
        issue_command: &VerdictCommand,
        apply_command: &TaskCommand,
        replayed: bool,
    ) -> ExecuteTaskCommandResponse {
        let verdict_response = guided_verdict_response(issue_command, true);
        let verdict = verdict_response
            .authority_result
            .as_ref()
            .and_then(|result| result.verdict.as_ref())
            .expect("issued verdict");
        let scope = verdict.scope.as_ref().expect("verdict scope");
        let apply = match apply_command.command.as_ref() {
            Some(task_command::Command::ApplyFounderVerdict(apply)) => apply,
            _ => panic!("ApplyFounderVerdict command"),
        };
        let metadata = apply.meta.as_ref().expect("Apply metadata");
        let status = match FounderVerdictDecision::try_from(verdict.decision) {
            Ok(FounderVerdictDecision::Accept) => DomainTaskStatus::Completed,
            Ok(FounderVerdictDecision::Rework) => DomainTaskStatus::Rework,
            Ok(FounderVerdictDecision::Reject) => DomainTaskStatus::Rejected,
            _ => panic!("valid verdict decision"),
        };
        let task = TaskSnapshot {
            task_id: scope.task_id.clone(),
            revision: scope.task_revision + 1,
            work_revision: scope.work_revision,
            status: status as i32,
            artifact_set_id: Some(scope.artifact_set_id.clone()),
            verification_artifact_id: Some(scope.verification_artifact_id.clone()),
            founder_verdict_id: Some(verdict.founder_verdict_id.clone()),
            acceptance_contract_ref: scope.acceptance_contract_ref.clone(),
            ..Default::default()
        };
        let event = egopulse_domain_contracts::v01::egopulse::task::v1::TaskEvent {
            event_id: "task-event:guided-verdict-applied:1".to_owned(),
            command_id: metadata.command_id.clone(),
            kind: TaskEventKind::VerdictApplied as i32,
            task_id: scope.task_id.clone(),
            expected_revision: scope.task_revision,
            resulting_revision: task.revision,
            work_revision: scope.work_revision,
            authenticated_principal_id: "founder:guided-verdict".to_owned(),
            authority_ref: "authority:task".to_owned(),
            idempotency_key: metadata.idempotency_key.clone(),
            request_digest_sha256: metadata.request_digest_sha256.clone(),
            correlation_id: metadata.correlation_id.clone(),
            causation_id: metadata.causation_id.clone(),
            evidence_refs: vec![
                verdict.founder_verdict_id.clone(),
                format!("founder-verdict:{}@issued", verdict.founder_verdict_id),
                format!("founder-verdict-state:{}@{}", verdict.founder_verdict_id, 1),
            ],
            occurred_at: metadata.issued_at,
            snapshot: Some(task.clone()),
        };
        ExecuteTaskCommandResponse {
            authority_result: Some(TaskCommandResult {
                replayed,
                outcome: Some(task_command_result::Outcome::Task(task)),
                committed_event: Some(event),
            }),
            await_token: None,
            gateway_error: None,
        }
    }

    fn approval_position(sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: "epoch:approval-watch".to_owned(),
            sequence,
            projected_at: Some(Timestamp {
                seconds: sequence as i64,
                nanos: 0,
            }),
        }
    }

    fn approval_view(
        approval_request_id: impl Into<String>,
        position: &ProjectionPosition,
        action_kind: Option<i32>,
    ) -> HarnessApprovalView {
        let approval_request_id = approval_request_id.into();
        HarnessApprovalView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1.HarnessApprovalView".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "a".repeat(64),
                }),
                position: Some(position.clone()),
                source_revisions: vec![SourceRevision {
                    domain: SourceDomain::PolicyDecision as i32,
                    aggregate_id: approval_request_id.clone(),
                    revision: 1,
                    last_event_id: format!("event:{approval_request_id}"),
                }],
                health: ProjectionHealth::Ready as i32,
                stale: false,
                safe_health_reason_code: None,
            }),
            approval_request_id: approval_request_id.clone(),
            task_id: format!("task:{approval_request_id}"),
            run_id: format!("run:{approval_request_id}"),
            step_id: format!("step:{approval_request_id}"),
            attempt_id: format!("attempt:{approval_request_id}"),
            dispatch_id: format!("dispatch:{approval_request_id}"),
            fencing_token: 1,
            kind: 1,
            action_digest_sha256: "b".repeat(64),
            requested_scope_ref: "scope:test".to_owned(),
            display_summary_ref: "summary:test".to_owned(),
            display_summary: Some(approval_test_summary()),
            request_observation_id: format!("observation:{approval_request_id}"),
            request_observation_sequence: 1,
            request_lifecycle: 1,
            request_revision: 1,
            policy_decision: None,
            available_actions: action_kind
                .map(|kind| AvailableAction {
                    kind,
                    owning_authority: "PolicyDecisionAuthority".to_owned(),
                    derivation_rule_ref: "rule:approval-actionability".to_owned(),
                    explicit_confirmation_required: true,
                    reason_code: None,
                })
                .into_iter()
                .collect(),
            redactions: Vec::new(),
        }
    }

    fn approval_page(
        position: &ProjectionPosition,
        views: Vec<HarnessApprovalView>,
        next_page_cursor: Option<&str>,
    ) -> ListHarnessApprovalViewsResponse {
        ListHarnessApprovalViewsResponse {
            views,
            next_page_cursor: next_page_cursor.map(str::to_owned),
            snapshot_position: Some(position.clone()),
            error: None,
        }
    }

    fn approval_test_summary()
    -> egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDisplaySummary {
        egopulse_domain_contracts::approval_display::seal_approval_display_summary(
            egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDisplaySummary {
                state: 1,
                summary_ref: "summary:test".to_owned(),
                action_digest_sha256: "b".repeat(64),
                source_binding_sha256: "c".repeat(64),
                command_preview: "cargo test".to_owned(),
                working_directory_label: ".".to_owned(),
                policy_code: "egopulse.approval-display/v1".to_owned(),
                ..Default::default()
            },
        )
    }

    fn guided_approval_input(decision: GuidedApprovalDecision) -> GuidedApprovalDecisionInput {
        GuidedApprovalDecisionInput {
            approval_request_id: "approval:guided:1".to_owned(),
            decision,
            reason_code: "  founder-reviewed  ".to_owned(),
            confirmation_proof_ref: Some("proof:approval:1".to_owned()),
            reviewed_summary_digest_sha256: Some(approval_test_summary().summary_digest_sha256),
        }
    }

    fn local_api_error(code: LocalApiErrorCode) -> LocalApiError {
        LocalApiError {
            code: code as i32,
            safe_fingerprint: "approval/guided/test/v1".to_owned(),
            retryable: false,
            required_action_code: Some("REFRESH_APPROVAL".to_owned()),
            current_position: None,
            correlation_id: "correlation:approval:guided".to_owned(),
        }
    }

    #[allow(deprecated)]
    fn guided_approval_response(
        decision: GuidedApprovalDecision,
        replayed: bool,
        gateway_error: Option<LocalApiError>,
    ) -> DecideHarnessApprovalResponse {
        DecideHarnessApprovalResponse {
            await_token: None,
            gateway_error,
            policy_authority_result: None,
            sanitized_authority_result: Some(HarnessApprovalAuthorityResult {
                committed: true,
                replayed,
                authority_decision_ref: "policy-decision:guided:1".to_owned(),
                decision: decision.wire_value(),
                state: HarnessApprovalDecisionStateKind::Issued as i32,
                state_revision: 1,
                expires_at: None,
                error_code: PolicyDecisionErrorCode::Unspecified as i32,
                safe_error_fingerprint: None,
            }),
        }
    }

    fn sealed_guided_approval_command(
        kernel: &ClientKernel,
        position: &ProjectionPosition,
        input: GuidedApprovalDecisionInput,
        now: SystemTime,
    ) -> IssueHarnessApprovalDecisionCommand {
        use std::cell::RefCell;

        let decision = input.decision;
        let request = RefCell::new(None);
        block_on_ready(decide_guided_approval_via(
            kernel,
            input,
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(
                        approval_view(
                            "approval:guided:1",
                            position,
                            Some(AvailableActionKind::DecideHarnessApproval as i32),
                        ),
                    )),
                }))
            },
            |value| {
                request.replace(Some(value));
                std::future::ready(Ok(guided_approval_response(decision, false, None)))
            },
        ))
        .expect("guided approval command");
        request
            .into_inner()
            .expect("Decide request")
            .command
            .expect("sealed command")
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn watch_position(epoch: &str, sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: epoch.to_owned(),
            sequence,
            projected_at: Some(Timestamp {
                seconds: sequence as i64,
                nanos: 0,
            }),
        }
    }

    fn watch_view(position: &ProjectionPosition, task_id: &str, revision: u64) -> TaskView {
        TaskView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1/TaskView".to_owned(),
                    version: "0.1.0".to_owned(),
                    sha256: "a".repeat(64),
                }),
                position: Some(position.clone()),
                source_revisions: vec![SourceRevision {
                    domain: SourceDomain::Task as i32,
                    aggregate_id: task_id.to_owned(),
                    revision,
                    last_event_id: format!("event:{task_id}:{revision}"),
                }],
                health: 1,
                stale: false,
                safe_health_reason_code: None,
            }),
            task: Some(TaskSnapshot {
                task_id: task_id.to_owned(),
                revision,
                ..TaskSnapshot::default()
            }),
            ..TaskView::default()
        }
    }

    fn governed_test_view(
        position: &ProjectionPosition,
        suffix: &str,
        task_status: TaskStatus,
        run_status: RunStatus,
        step_status: StepStatus,
        attempt_status: AttemptStatus,
        recovery_class: RecoveryClass,
    ) -> TaskView {
        let task_id = format!("task:{suffix}");
        let run_id = format!("run:{suffix}");
        let first_step_id = format!("step:{suffix}");
        let second_step_id = format!("step:{suffix}:second");
        let first_history_id = format!("attempt:{suffix}:history");
        let first_current_id = format!("attempt:{suffix}");
        let second_history_id = format!("attempt:{suffix}:second:history");
        let second_current_id = format!("attempt:{suffix}:second");
        let attempt = |attempt_id: String,
                       step_id: &str,
                       attempt_number: u32,
                       status: AttemptStatus,
                       recovery: RecoveryClass| AttemptSnapshot {
            attempt_id,
            run_id: run_id.clone(),
            step_id: step_id.to_owned(),
            revision: u64::from(attempt_number) + 5,
            attempt_number,
            status: status as i32,
            harness_id: "sensitive-harness-canary".to_owned(),
            capability_profile_ref: Some(ContractReference {
                contract_id: "sensitive-capability-canary".to_owned(),
                version: "v1".to_owned(),
                sha256: "b".repeat(64),
            }),
            workspace_ref: "sensitive-workspace-canary".to_owned(),
            dispatch_id: Some("sensitive-dispatch-canary".to_owned()),
            dispatch_fingerprint: Some("c".repeat(64)),
            harness_session_ref: Some("sensitive-session-canary".to_owned()),
            last_harness_sequence: if attempt_number == 1 { 0 } else { 42 },
            latest_checkpoint_id: (attempt_number > 1)
                .then(|| "sensitive-checkpoint-canary".to_owned()),
            recovery_class: recovery as i32,
            hold_reason_code: (matches!(
                status,
                AttemptStatus::OutcomeUnknown | AttemptStatus::Reconciling | AttemptStatus::Held
            ))
            .then(|| "MANUAL_RECOVERY_REQUIRED".to_owned()),
            ..AttemptSnapshot::default()
        };
        TaskView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1/TaskView".to_owned(),
                    version: "0.1.0".to_owned(),
                    sha256: "a".repeat(64),
                }),
                position: Some(position.clone()),
                source_revisions: vec![
                    SourceRevision {
                        domain: SourceDomain::Task as i32,
                        aggregate_id: task_id.clone(),
                        revision: 4,
                        last_event_id: format!("event:{task_id}:4"),
                    },
                    SourceRevision {
                        domain: SourceDomain::Collaboration as i32,
                        aggregate_id: run_id.clone(),
                        revision: 5,
                        last_event_id: format!("event:{run_id}:5"),
                    },
                ],
                health: ProjectionHealth::Ready as i32,
                stale: false,
                safe_health_reason_code: None,
            }),
            task: Some(TaskSnapshot {
                task_id: task_id.clone(),
                revision: 4,
                work_revision: 2,
                status: task_status as i32,
                hold_reason_code: (task_status == TaskStatus::Held)
                    .then(|| "MANUAL_RECOVERY_REQUIRED".to_owned()),
                current_run_id: Some(run_id.clone()),
                ..TaskSnapshot::default()
            }),
            collaboration: Some(CollaborationSnapshot {
                run: Some(RunSnapshot {
                    run_id: run_id.clone(),
                    revision: 5,
                    task_id,
                    task_revision_at_creation: 2,
                    work_revision: 2,
                    status: run_status as i32,
                    step_ids: vec![first_step_id.clone(), second_step_id.clone()],
                    hold_reason_code: (run_status == RunStatus::Held)
                        .then(|| "MANUAL_RECOVERY_REQUIRED".to_owned()),
                    ..RunSnapshot::default()
                }),
                steps: vec![
                    StepSnapshot {
                        step_id: first_step_id.clone(),
                        run_id: run_id.clone(),
                        revision: 3,
                        status: step_status as i32,
                        attempt_ids: vec![first_history_id.clone(), first_current_id.clone()],
                        current_attempt_id: Some(first_current_id.clone()),
                        hold_reason_code: (step_status == StepStatus::Held)
                            .then(|| "MANUAL_RECOVERY_REQUIRED".to_owned()),
                        ..StepSnapshot::default()
                    },
                    StepSnapshot {
                        step_id: second_step_id.clone(),
                        run_id: run_id.clone(),
                        revision: 4,
                        status: step_status as i32,
                        attempt_ids: vec![second_history_id.clone(), second_current_id.clone()],
                        current_attempt_id: Some(second_current_id.clone()),
                        hold_reason_code: (step_status == StepStatus::Held)
                            .then(|| "MANUAL_RECOVERY_REQUIRED".to_owned()),
                        ..StepSnapshot::default()
                    },
                ],
                attempts: vec![
                    attempt(
                        first_history_id,
                        &first_step_id,
                        1,
                        AttemptStatus::Interrupted,
                        RecoveryClass::RetryIdempotent,
                    ),
                    attempt(
                        first_current_id,
                        &first_step_id,
                        2,
                        attempt_status,
                        recovery_class,
                    ),
                    attempt(
                        second_history_id,
                        &second_step_id,
                        1,
                        AttemptStatus::Interrupted,
                        RecoveryClass::RetryIdempotent,
                    ),
                    attempt(
                        second_current_id,
                        &second_step_id,
                        2,
                        attempt_status,
                        recovery_class,
                    ),
                ],
            }),
            ..TaskView::default()
        }
    }

    fn governed_no_run_view(position: &ProjectionPosition, task_id: impl Into<String>) -> TaskView {
        let task_id = task_id.into();
        TaskView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1/TaskView".to_owned(),
                    version: "0.1.0".to_owned(),
                    sha256: "a".repeat(64),
                }),
                position: Some(position.clone()),
                source_revisions: vec![SourceRevision {
                    domain: SourceDomain::Task as i32,
                    aggregate_id: task_id.clone(),
                    revision: 1,
                    last_event_id: format!("event:{task_id}:1"),
                }],
                health: ProjectionHealth::Ready as i32,
                stale: false,
                safe_health_reason_code: None,
            }),
            task: Some(TaskSnapshot {
                task_id,
                revision: 1,
                work_revision: 1,
                status: TaskStatus::Ready as i32,
                ..TaskSnapshot::default()
            }),
            ..TaskView::default()
        }
    }

    fn governed_task_page(
        position: &ProjectionPosition,
        views: Vec<TaskView>,
        next_page_cursor: Option<&str>,
    ) -> ListTaskViewsResponse {
        ListTaskViewsResponse {
            views,
            next_page_cursor: next_page_cursor.map(str::to_owned),
            snapshot_position: Some(position.clone()),
            error: None,
        }
    }

    fn watch_frame(
        kind: StreamFrameKind,
        position: ProjectionPosition,
        view: Option<TaskView>,
        reset_reason_code: Option<&str>,
    ) -> TaskViewStreamFrame {
        TaskViewStreamFrame {
            kind: kind as i32,
            position: Some(position),
            snapshot: view,
            reset_reason_code: reset_reason_code.map(str::to_owned),
        }
    }

    #[test]
    fn governed_task_states_map_execution_and_recovery_without_sensitive_material() {
        let position = watch_position("epoch:u05", 20);
        let cases = [
            (
                "running",
                TaskStatus::Active,
                RunStatus::Active,
                StepStatus::Active,
                AttemptStatus::Running,
                RecoveryClass::ResumeSafe,
            ),
            (
                "outcome-unknown",
                TaskStatus::Interrupted,
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::OutcomeUnknown,
                RecoveryClass::ReconcileBeforeRetry,
            ),
            (
                "reconciling",
                TaskStatus::Interrupted,
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::Reconciling,
                RecoveryClass::ReconcileBeforeRetry,
            ),
            (
                "held",
                TaskStatus::Held,
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::Held,
                RecoveryClass::ManualOnly,
            ),
            (
                "interrupted",
                TaskStatus::Interrupted,
                RunStatus::Active,
                StepStatus::Active,
                AttemptStatus::Interrupted,
                RecoveryClass::RetryIdempotent,
            ),
        ];
        for (suffix, task_status, run_status, step_status, attempt_status, recovery_class) in cases
        {
            let view = governed_test_view(
                &position,
                suffix,
                task_status,
                run_status,
                step_status,
                attempt_status,
                recovery_class,
            );
            let state = governed_task_state_from_view(&view).expect("valid governed state");
            assert_eq!(state.status, task_status);
            assert_eq!(state.resume_status, None);
            assert_eq!(
                state.hold_reason,
                (task_status == TaskStatus::Held)
                    .then_some(GovernedHoldReason::ManualRecoveryRequired)
            );
            assert_eq!(state.projection.health, ProjectionHealth::Ready);
            assert!(!state.projection.stale);
            assert_eq!(state.projection.reason, None);
            let run = state.run.as_ref().expect("run state");
            assert_eq!(run.status, run_status);
            assert_eq!(run.work_revision, 2);
            assert_eq!(run.steps.len(), 2);
            for step in &run.steps {
                assert_eq!(step.status, step_status);
                assert_eq!(step.attempts.len(), 2);
                let historical = &step.attempts[0];
                assert_eq!(historical.attempt_number, 1);
                assert_eq!(historical.status, AttemptStatus::Interrupted);
                assert_eq!(historical.recovery_class, RecoveryClass::RetryIdempotent);
                assert_eq!(historical.last_harness_sequence, 0);
                assert!(!historical.checkpoint_reference_recorded);
                let current = &step.attempts[1];
                assert_eq!(
                    step.current_attempt_id.as_deref(),
                    Some(current.attempt_id.as_str())
                );
                assert_eq!(current.attempt_number, 2);
                assert_eq!(current.status, attempt_status);
                assert_eq!(current.recovery_class, recovery_class);
                assert_eq!(current.last_harness_sequence, 42);
                assert!(current.checkpoint_reference_recorded);
            }
            let safe_debug = format!("{state:?}");
            for sensitive in [
                "sensitive-harness-canary",
                "sensitive-capability-canary",
                "sensitive-workspace-canary",
                "sensitive-dispatch-canary",
                "sensitive-session-canary",
                "sensitive-checkpoint-canary",
            ] {
                assert!(!safe_debug.contains(sensitive));
            }
        }

        let mut unclassified = governed_test_view(
            &position,
            "opaque-hold",
            TaskStatus::Held,
            RunStatus::Held,
            StepStatus::Held,
            AttemptStatus::Held,
            RecoveryClass::ManualOnly,
        );
        let collaboration = unclassified.collaboration.as_mut().expect("collaboration");
        unclassified.task.as_mut().expect("task").hold_reason_code =
            Some("sensitive-hold-reason-canary".to_owned());
        collaboration.run.as_mut().expect("run").hold_reason_code =
            Some("sensitive-hold-reason-canary".to_owned());
        for step in &mut collaboration.steps {
            step.hold_reason_code = Some("sensitive-hold-reason-canary".to_owned());
        }
        for attempt in &mut collaboration.attempts {
            attempt.hold_reason_code = Some("sensitive-hold-reason-canary".to_owned());
        }
        let safe = governed_task_state_from_view(&unclassified).expect("unclassified hold");
        assert_eq!(safe.hold_reason, Some(GovernedHoldReason::Unclassified));
        let run = safe.run.as_ref().expect("run");
        assert_eq!(run.hold_reason, Some(GovernedHoldReason::Unclassified));
        assert!(run.steps.iter().all(|step| {
            step.hold_reason == Some(GovernedHoldReason::Unclassified)
                && step
                    .attempts
                    .iter()
                    .all(|attempt| attempt.hold_reason == Some(GovernedHoldReason::Unclassified))
        }));
        assert!(!format!("{safe:?}").contains("sensitive-hold-reason-canary"));

        let mut resumable = governed_test_view(
            &position,
            "resumable",
            TaskStatus::Interrupted,
            RunStatus::Active,
            StepStatus::Active,
            AttemptStatus::Interrupted,
            RecoveryClass::ResumeSafe,
        );
        resumable.task.as_mut().expect("task").resume_status = TaskStatus::Active as i32;
        assert_eq!(
            governed_task_state_from_view(&resumable)
                .expect("valid resume status")
                .resume_status,
            Some(TaskStatus::Active)
        );

        for (raw, expected) in [
            (
                "DEPENDENCY_PROJECTION_PENDING",
                GovernedProjectionReason::DependencyProjectionPending,
            ),
            (
                "PROJECTION_NOT_READY",
                GovernedProjectionReason::ProjectionNotReady,
            ),
            (
                "TASK_PROJECTION_INVALID",
                GovernedProjectionReason::TaskProjectionInvalid,
            ),
            (
                "sensitive-projection-reason-canary",
                GovernedProjectionReason::Unclassified,
            ),
        ] {
            let mut view = governed_test_view(
                &position,
                "projection-reason",
                TaskStatus::Active,
                RunStatus::Active,
                StepStatus::Active,
                AttemptStatus::Running,
                RecoveryClass::ResumeSafe,
            );
            view.metadata
                .as_mut()
                .expect("metadata")
                .safe_health_reason_code = Some(raw.to_owned());
            let state = governed_task_state_from_view(&view).expect("safe projection reason");
            assert_eq!(state.projection.reason, Some(expected));
            assert!(!format!("{state:?}").contains("sensitive-projection-reason-canary"));
        }

        let mut stale = governed_test_view(
            &position,
            "stale",
            TaskStatus::Active,
            RunStatus::Active,
            StepStatus::Active,
            AttemptStatus::Running,
            RecoveryClass::ResumeSafe,
        );
        stale.collaboration = None;
        let metadata = stale.metadata.as_mut().expect("metadata");
        metadata.stale = true;
        metadata.safe_health_reason_code = Some("DEPENDENCY_PROJECTION_PENDING".to_owned());
        metadata
            .source_revisions
            .retain(|source| source.domain != SourceDomain::Collaboration as i32);
        let state = governed_task_state_from_view(&stale).expect("stale dependency is explicit");
        assert!(state.projection.stale);
        assert_eq!(
            state.projection.reason,
            Some(GovernedProjectionReason::DependencyProjectionPending)
        );
        assert!(state.run.is_none());
        assert_eq!(state.status, TaskStatus::Active);

        stale
            .metadata
            .as_mut()
            .expect("metadata")
            .safe_health_reason_code = Some("PROJECTION_NOT_READY".to_owned());
        assert!(matches!(
            governed_task_state_from_view(&stale),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task omitted its current Run without dependency-pending state"
            ))
        ));

        let metadata = stale.metadata.as_mut().expect("metadata");
        metadata.safe_health_reason_code = Some("DEPENDENCY_PROJECTION_PENDING".to_owned());
        metadata.stale = false;
        assert!(matches!(
            governed_task_state_from_view(&stale),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task omitted its current Run without dependency-pending state"
            ))
        ));
    }

    #[test]
    fn governed_task_mapping_fails_closed_for_unknown_enums_and_lineage_drift() {
        let position = watch_position("epoch:u05-integrity", 30);
        let valid = || {
            governed_test_view(
                &position,
                "integrity",
                TaskStatus::Interrupted,
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::OutcomeUnknown,
                RecoveryClass::ReconcileBeforeRetry,
            )
        };
        let mut invalid = Vec::new();

        for status in [i32::MAX, TaskStatus::Unspecified as i32] {
            let mut value = valid();
            value.task.as_mut().expect("task").status = status;
            invalid.push(value);
        }
        let mut value = valid();
        value.task.as_mut().expect("task").work_revision = 0;
        invalid.push(value);
        let mut value = valid();
        value.task.as_mut().expect("task").resume_status = i32::MAX;
        invalid.push(value);
        for status in [i32::MAX, RunStatus::Unspecified as i32] {
            let mut value = valid();
            value
                .collaboration
                .as_mut()
                .expect("collaboration")
                .run
                .as_mut()
                .expect("run")
                .status = status;
            invalid.push(value);
        }
        for status in [i32::MAX, StepStatus::Unspecified as i32] {
            let mut value = valid();
            value.collaboration.as_mut().expect("collaboration").steps[0].status = status;
            invalid.push(value);
        }
        for status in [i32::MAX, AttemptStatus::Unspecified as i32] {
            let mut value = valid();
            value
                .collaboration
                .as_mut()
                .expect("collaboration")
                .attempts[0]
                .status = status;
            invalid.push(value);
        }
        for recovery in [i32::MAX, RecoveryClass::Unspecified as i32] {
            let mut value = valid();
            value
                .collaboration
                .as_mut()
                .expect("collaboration")
                .attempts[0]
                .recovery_class = recovery;
            invalid.push(value);
        }
        for health in [i32::MAX, ProjectionHealth::Unspecified as i32] {
            let mut value = valid();
            value.metadata.as_mut().expect("metadata").health = health;
            invalid.push(value);
        }
        let mut value = valid();
        value
            .collaboration
            .as_mut()
            .expect("collaboration")
            .run
            .as_mut()
            .expect("run")
            .task_id = "task:other".to_owned();
        invalid.push(value);
        let mut value = valid();
        value
            .collaboration
            .as_mut()
            .expect("collaboration")
            .run
            .as_mut()
            .expect("run")
            .step_ids = vec!["step:other".to_owned()];
        invalid.push(value);
        let mut value = valid();
        value.collaboration.as_mut().expect("collaboration").steps[0].run_id =
            "run:other".to_owned();
        invalid.push(value);
        let mut value = valid();
        value.collaboration.as_mut().expect("collaboration").steps[0].current_attempt_id =
            Some("attempt:other".to_owned());
        invalid.push(value);
        let mut value = valid();
        value
            .collaboration
            .as_mut()
            .expect("collaboration")
            .attempts[0]
            .step_id = "step:other".to_owned();
        invalid.push(value);

        let mut value = valid();
        value
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .retain(|source| source.domain != SourceDomain::Task as i32);
        invalid.push(value);
        let mut value = valid();
        let task_source = value.metadata.as_mut().expect("metadata").source_revisions[0].clone();
        value
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .push(task_source);
        invalid.push(value);
        let mut value = valid();
        value.metadata.as_mut().expect("metadata").source_revisions[0].aggregate_id =
            "task:other".to_owned();
        invalid.push(value);
        let mut value = valid();
        value.metadata.as_mut().expect("metadata").source_revisions[0].revision += 1;
        invalid.push(value);
        let mut value = valid();
        value
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .retain(|source| source.domain != SourceDomain::Collaboration as i32);
        invalid.push(value);
        let mut value = valid();
        let collaboration_source =
            value.metadata.as_mut().expect("metadata").source_revisions[1].clone();
        value
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .push(collaboration_source);
        invalid.push(value);
        let mut value = valid();
        value.metadata.as_mut().expect("metadata").source_revisions[1].aggregate_id =
            "run:other".to_owned();
        invalid.push(value);
        let mut value = valid();
        value.metadata.as_mut().expect("metadata").source_revisions[1].revision += 1;
        invalid.push(value);

        for value in invalid {
            assert!(matches!(
                governed_task_state_from_view(&value),
                Err(ClientGovernedTaskError::Protocol(_))
            ));
        }

        let mut no_run = governed_no_run_view(&position, "task:no-run");
        no_run
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .push(SourceRevision {
                domain: SourceDomain::Artifact as i32,
                aggregate_id: "artifact-set:safe".to_owned(),
                revision: 1,
                last_event_id: "event:artifact-set:safe:1".to_owned(),
            });
        assert!(governed_task_state_from_view(&no_run).is_ok());

        let mut duplicate_other_domain = no_run.clone();
        duplicate_other_domain
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .push(SourceRevision {
                domain: SourceDomain::Artifact as i32,
                aggregate_id: "artifact-set:other".to_owned(),
                revision: 2,
                last_event_id: "event:artifact-set:other:2".to_owned(),
            });
        assert!(matches!(
            governed_task_state_from_view(&duplicate_other_domain),
            Err(ClientGovernedTaskError::Protocol(
                "governed projection source domain is duplicated"
            ))
        ));

        let mut unexpected_collaboration = governed_no_run_view(&position, "task:no-run");
        unexpected_collaboration
            .metadata
            .as_mut()
            .expect("metadata")
            .source_revisions
            .push(SourceRevision {
                domain: SourceDomain::Collaboration as i32,
                aggregate_id: "run:unexpected".to_owned(),
                revision: 1,
                last_event_id: "event:run:unexpected:1".to_owned(),
            });
        assert!(matches!(
            governed_task_state_from_view(&unexpected_collaboration),
            Err(ClientGovernedTaskError::Protocol(
                "governed Collaboration source revision binding is invalid"
            ))
        ));
    }

    #[test]
    fn governed_task_baseline_read_is_permission_first_and_follows_one_snapshot() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(12_000);
        let kernel = authenticated_kernel("founder:u05", "session:u05", "local.task.read", now);
        let snapshot = watch_position("epoch:u05-baseline", 100);
        let older = watch_position("epoch:u05-baseline", 90);
        let mut pages = VecDeque::from([
            Ok(governed_task_page(
                &snapshot,
                vec![governed_no_run_view(&older, "task:b")],
                Some("cursor:2"),
            )),
            Ok(governed_task_page(
                &snapshot,
                vec![governed_no_run_view(&snapshot, "task:a")],
                None,
            )),
        ]);
        let requests = RefCell::new(Vec::new());
        let baseline = block_on_ready(read_governed_task_baseline_via(&kernel, now, |request| {
            requests.borrow_mut().push(request);
            std::future::ready(pages.pop_front().expect("baseline page"))
        }))
        .expect("complete governed Task baseline");
        assert_eq!(baseline.position().epoch, snapshot.epoch);
        assert_eq!(baseline.position().sequence, snapshot.sequence);
        assert_eq!(
            baseline
                .tasks()
                .into_iter()
                .map(|task| task.task_id.as_str())
                .collect::<Vec<_>>(),
            ["task:a", "task:b"]
        );
        let requests = requests.into_inner();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].page_size, 100);
        assert!(requests[0].status_filter.is_empty());
        assert!(requests[0].minimum_position.is_none());
        assert!(requests[0].page_cursor.is_none());
        assert_eq!(requests[1].page_cursor.as_deref(), Some("cursor:2"));
        assert_eq!(requests[0].client, requests[1].client);
        let metadata = requests[0].client.as_ref().expect("client metadata");
        assert_eq!(metadata.session_id, "session:u05");
        assert_eq!(metadata.surface, ClientSurface::Cli as i32);

        let denied = authenticated_kernel(
            "founder:u05",
            "session:u05-denied",
            "local.context.revoke",
            now,
        );
        let denied_calls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(read_governed_task_baseline_via(
                &denied,
                now,
                |_request| {
                    denied_calls.set(denied_calls.get() + 1);
                    std::future::ready(Ok(governed_task_page(&snapshot, Vec::new(), None)))
                },
            )),
            Err(ClientGovernedTaskError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.task.read"
        ));
        assert_eq!(denied_calls.get(), 0);
    }

    #[test]
    fn governed_task_baseline_rejects_cursor_identity_position_and_capacity_drift() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(12_100);
        let kernel =
            authenticated_kernel("founder:u05", "session:u05-failure", "local.task.read", now);
        let position = watch_position("epoch:u05-failure", 100);
        let other_position = watch_position("epoch:u05-failure", 101);

        let mut stalled = VecDeque::from([
            Ok(governed_task_page(
                &position,
                vec![governed_no_run_view(&position, "task:1")],
                Some("cursor:same"),
            )),
            Ok(governed_task_page(
                &position,
                vec![governed_no_run_view(&position, "task:2")],
                Some("cursor:same"),
            )),
        ]);
        assert!(matches!(
            block_on_ready(read_governed_task_baseline_via(&kernel, now, |_request| {
                std::future::ready(stalled.pop_front().expect("stalled page"))
            },)),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline cursor did not advance"
            ))
        ));

        let duplicate = governed_no_run_view(&position, "task:duplicate");
        assert!(matches!(
            compile_governed_task_baseline(vec![
                governed_task_page(&position, vec![duplicate.clone()], Some("cursor:2")),
                governed_task_page(&position, vec![duplicate], None),
            ]),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline identity is duplicated"
            ))
        ));

        assert!(matches!(
            compile_governed_task_baseline(vec![
                governed_task_page(
                    &position,
                    vec![governed_no_run_view(&position, "task:position:1")],
                    Some("cursor:2"),
                ),
                governed_task_page(
                    &other_position,
                    vec![governed_no_run_view(&other_position, "task:position:2")],
                    None,
                ),
            ]),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline position changed across pages"
            ))
        ));

        for invalid_cursor in ["   ", "cursor:\ninvalid"] {
            let mut page = Some(Ok(governed_task_page(
                &position,
                vec![governed_no_run_view(&position, "task:cursor")],
                Some(invalid_cursor),
            )));
            assert!(matches!(
                block_on_ready(read_governed_task_baseline_via(&kernel, now, |_request| {
                    std::future::ready(page.take().expect("cursor page"))
                },)),
                Err(ClientGovernedTaskError::Protocol(
                    "governed Task baseline cursor did not advance"
                ))
            ));
        }

        let mut empty_page = Some(Ok(governed_task_page(
            &position,
            Vec::new(),
            Some("cursor:empty"),
        )));
        assert!(matches!(
            block_on_ready(read_governed_task_baseline_via(&kernel, now, |_request| {
                std::future::ready(empty_page.take().expect("empty page"))
            },)),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline cursor did not advance"
            ))
        ));

        assert!(matches!(
            compile_governed_task_baseline(vec![
                governed_task_page(
                    &position,
                    vec![governed_no_run_view(&position, "task:complete")],
                    None,
                ),
                governed_task_page(
                    &position,
                    vec![governed_no_run_view(&position, "task:after-complete")],
                    None,
                ),
            ]),
            Err(ClientGovernedTaskError::Protocol(
                "governed Task baseline contained pages after completion"
            ))
        ));

        let mut exact_limit = VecDeque::new();
        for page_index in 0..10 {
            let views = (0..100)
                .map(|item_index| {
                    governed_no_run_view(
                        &position,
                        format!("task:limit:{page_index:02}:{item_index:03}"),
                    )
                })
                .collect();
            let next = (page_index < 9).then(|| format!("cursor:limit:{}", page_index + 1));
            exact_limit.push_back(Ok(governed_task_page(&position, views, next.as_deref())));
        }
        let exact_dispatches = Cell::new(0_u64);
        let exact_baseline =
            block_on_ready(read_governed_task_baseline_via(&kernel, now, |_request| {
                exact_dispatches.set(exact_dispatches.get() + 1);
                std::future::ready(exact_limit.pop_front().expect("exact limit page"))
            }))
            .expect("exact 1000-item baseline");
        assert_eq!(exact_baseline.tasks().len(), 1_000);
        assert_eq!(exact_dispatches.get(), 10);

        let mut oversized = VecDeque::new();
        for page_index in 0..=10 {
            let item_count = if page_index == 10 { 1 } else { 100 };
            let views = (0..item_count)
                .map(|item_index| {
                    governed_no_run_view(&position, format!("task:{page_index:02}:{item_index:03}"))
                })
                .collect();
            let next = (page_index < 10).then(|| format!("cursor:{}", page_index + 1));
            oversized.push_back(Ok(governed_task_page(&position, views, next.as_deref())));
        }
        let dispatches = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(read_governed_task_baseline_via(&kernel, now, |_request| {
                dispatches.set(dispatches.get() + 1);
                std::future::ready(oversized.pop_front().expect("oversized page"))
            },)),
            Err(ClientGovernedTaskError::BaselineLimitExceeded)
        ));
        assert_eq!(dispatches.get(), 11);
    }

    #[test]
    fn governed_task_session_applies_once_and_honors_replay_heartbeat_and_reset_barrier() {
        let floor = watch_position("epoch:u05-session", 100);
        let next = watch_position("epoch:u05-session", 101);
        let heartbeat = watch_position("epoch:u05-session", 102);
        let reset = watch_position("epoch:u05-session", 103);
        let first_view = governed_no_run_view(&next, "task:a");
        let second_view = governed_no_run_view(&next, "task:b");
        let first_frame = watch_frame(
            StreamFrameKind::Snapshot,
            next.clone(),
            Some(first_view.clone()),
            None,
        );
        let mut processor = TaskWatchProcessor::default();
        let mut tasks = BTreeMap::new();
        let mut last_position = governed_position(&floor).expect("floor");

        let first = block_on_ready(next_governed_task_session_update_via(
            &mut processor,
            &mut tasks,
            &mut last_position,
            || std::future::ready(Ok(Some(first_frame.clone()))),
        ))
        .expect("first applied update");
        assert_eq!(first.classification, TaskWatchClassification::Applied);
        let second = block_on_ready(next_governed_task_session_update_via(
            &mut processor,
            &mut tasks,
            &mut last_position,
            || {
                std::future::ready(Ok(Some(watch_frame(
                    StreamFrameKind::Snapshot,
                    next.clone(),
                    Some(second_view),
                    None,
                ))))
            },
        ))
        .expect("same-position distinct Task applied");
        assert_eq!(second.classification, TaskWatchClassification::Applied);
        assert_eq!(
            tasks.keys().map(String::as_str).collect::<Vec<_>>(),
            ["task:a", "task:b"]
        );

        let facts = tasks.clone();
        let replay = block_on_ready(next_governed_task_session_update_via(
            &mut processor,
            &mut tasks,
            &mut last_position,
            || std::future::ready(Ok(Some(first_frame))),
        ))
        .expect("exact replay");
        assert_eq!(replay.classification, TaskWatchClassification::Replay);
        assert_eq!(tasks, facts);

        let heartbeat_update = block_on_ready(next_governed_task_session_update_via(
            &mut processor,
            &mut tasks,
            &mut last_position,
            || {
                std::future::ready(Ok(Some(watch_frame(
                    StreamFrameKind::Heartbeat,
                    heartbeat.clone(),
                    None,
                    None,
                ))))
            },
        ))
        .expect("heartbeat");
        assert_eq!(
            heartbeat_update.classification,
            TaskWatchClassification::Heartbeat
        );
        assert_eq!(tasks, facts);
        assert_eq!(last_position.sequence, 102);

        let reset_update = block_on_ready(next_governed_task_session_update_via(
            &mut processor,
            &mut tasks,
            &mut last_position,
            || {
                std::future::ready(Ok(Some(watch_frame(
                    StreamFrameKind::ResetRequired,
                    reset,
                    None,
                    Some("retention-floor-advanced"),
                ))))
            },
        ))
        .expect("reset frame is reported once");
        assert_eq!(
            reset_update.classification,
            TaskWatchClassification::ResetRequired
        );
        assert_eq!(tasks, facts);
        let polls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(next_governed_task_session_update_via(
                &mut processor,
                &mut tasks,
                &mut last_position,
                || {
                    polls.set(polls.get() + 1);
                    std::future::ready(Ok(None))
                },
            )),
            Err(ClientGovernedTaskError::ResetBarrier)
        ));
        assert_eq!(polls.get(), 0);
    }

    #[test]
    fn task_watch_processor_classifies_replay_and_enforces_reset_barrier() {
        let mut processor = TaskWatchProcessor::default();
        let position = watch_position("epoch:watch", 7);
        let first = watch_frame(
            StreamFrameKind::Snapshot,
            position.clone(),
            Some(watch_view(&position, "task:one", 1)),
            None,
        );
        assert_eq!(
            processor.process(first.clone()).unwrap().classification,
            TaskWatchClassification::Applied
        );
        assert_eq!(
            processor.process(first).unwrap().classification,
            TaskWatchClassification::Replay
        );
        let second = watch_frame(
            StreamFrameKind::Snapshot,
            position.clone(),
            Some(watch_view(&position, "task:two", 1)),
            None,
        );
        assert_eq!(
            processor.process(second).unwrap().classification,
            TaskWatchClassification::Applied
        );
        assert_eq!(
            processor
                .process(watch_frame(
                    StreamFrameKind::Heartbeat,
                    position.clone(),
                    None,
                    None,
                ))
                .unwrap()
                .classification,
            TaskWatchClassification::Heartbeat
        );
        let reset_position = watch_position("epoch:watch", 8);
        let reset = processor
            .process(watch_frame(
                StreamFrameKind::ResetRequired,
                reset_position,
                None,
                Some("projection_compacted"),
            ))
            .unwrap();
        assert_eq!(reset.classification, TaskWatchClassification::ResetRequired);
        assert_eq!(
            reset.reset_reason_code.as_deref(),
            Some("projection_compacted")
        );
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Heartbeat,
                position,
                None,
                None,
            )),
            Err(ClientTaskWatchError::ResetBarrier)
        ));
    }

    #[test]
    fn task_watch_next_seam_blocks_message_after_reset_and_types_eof_and_transport() {
        let calls = Cell::new(0_u64);
        let mut processor = TaskWatchProcessor::default();
        let reset = watch_frame(
            StreamFrameKind::ResetRequired,
            watch_position("epoch:watch", 30),
            None,
            Some("projection_reset"),
        );
        let update = block_on_ready(next_task_watch_update_via(&mut processor, || {
            calls.set(calls.get() + 1);
            std::future::ready(Ok(Some(reset)))
        }))
        .unwrap()
        .unwrap();
        assert_eq!(
            update.classification,
            TaskWatchClassification::ResetRequired
        );
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            block_on_ready(next_task_watch_update_via(&mut processor, || {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(None))
            })),
            Err(ClientTaskWatchError::ResetBarrier)
        ));
        assert_eq!(calls.get(), 1, "reset barrier polled the underlying stream");

        let mut processor = TaskWatchProcessor::default();
        assert!(
            block_on_ready(next_task_watch_update_via(&mut processor, || {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(None))
            }))
            .unwrap()
            .is_none()
        );
        assert_eq!(calls.get(), 2);

        let mut processor = TaskWatchProcessor::default();
        assert!(matches!(
            block_on_ready(next_task_watch_update_via(&mut processor, || {
                calls.set(calls.get() + 1);
                std::future::ready(Err("tonic-status-unavailable".to_owned()))
            })),
            Err(ClientTaskWatchError::Transport(detail))
                if detail == "tonic-status-unavailable"
        ));
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn task_watch_processor_rejects_invalid_shapes_and_tracker_drift() {
        let position = watch_position("epoch:watch", 10);
        let view = watch_view(&position, "task:one", 1);
        for invalid in [
            watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(view.clone()),
                Some("unexpected"),
            ),
            watch_frame(
                StreamFrameKind::Heartbeat,
                position.clone(),
                None,
                Some("unexpected"),
            ),
            watch_frame(StreamFrameKind::ResetRequired, position.clone(), None, None),
            watch_frame(
                StreamFrameKind::ResetRequired,
                position.clone(),
                None,
                Some("unsafe reason"),
            ),
            watch_frame(
                StreamFrameKind::ResetRequired,
                position.clone(),
                Some(view.clone()),
                Some("projection_reset"),
            ),
        ] {
            assert!(matches!(
                TaskWatchProcessor::default().process(invalid),
                Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame
                ))
            ));
        }
        for unsafe_reason in [
            "x".repeat(129),
            "line\nbreak".to_owned(),
            "reset-原因".to_owned(),
        ] {
            assert!(matches!(
                TaskWatchProcessor::default().process(watch_frame(
                    StreamFrameKind::ResetRequired,
                    position.clone(),
                    None,
                    Some(&unsafe_reason),
                )),
                Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame
                ))
            ));
        }

        let mut missing_position =
            watch_frame(StreamFrameKind::Heartbeat, position.clone(), None, None);
        missing_position.position = None;
        assert!(matches!(
            TaskWatchProcessor::default().process(missing_position),
            Err(ClientTaskWatchError::Kernel(
                KernelError::StreamPositionInvalid
            ))
        ));

        let mut unknown = watch_frame(StreamFrameKind::Heartbeat, position.clone(), None, None);
        unknown.kind = 999;
        assert!(matches!(
            TaskWatchProcessor::default().process(unknown),
            Err(ClientTaskWatchError::Kernel(
                KernelError::UnknownStreamFrame
            ))
        ));

        let mut processor = TaskWatchProcessor::default();
        processor
            .process(watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(view.clone()),
                None,
            ))
            .unwrap();
        let changed = watch_view(&position, "task:one", 2);
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(changed),
                None,
            )),
            Err(ClientTaskWatchError::Kernel(
                KernelError::ConflictingStreamReplay
            ))
        ));

        let mut processor = TaskWatchProcessor::default();
        processor
            .process(watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(view),
                None,
            ))
            .unwrap();
        let other_epoch = watch_position("epoch:other", 11);
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Heartbeat,
                other_epoch,
                None,
                None,
            )),
            Err(ClientTaskWatchError::Kernel(
                KernelError::StreamResetMissing
            ))
        ));

        let mut processor = TaskWatchProcessor::default();
        processor
            .process(watch_frame(
                StreamFrameKind::Heartbeat,
                watch_position("epoch:watch", 20),
                None,
                None,
            ))
            .unwrap();
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Heartbeat,
                watch_position("epoch:watch", 19),
                None,
                None,
            )),
            Err(ClientTaskWatchError::Kernel(KernelError::StreamOutOfOrder))
        ));
    }

    #[test]
    fn task_watch_resume_pair_is_all_or_nothing() {
        assert_eq!(
            task_watch_resume_after(TaskWatchRequest::default()).unwrap(),
            None
        );
        assert_eq!(
            task_watch_resume_after(TaskWatchRequest {
                resume_epoch: Some("epoch:watch".to_owned()),
                resume_sequence: Some(12),
            })
            .unwrap(),
            Some(ProjectionPosition {
                epoch: "epoch:watch".to_owned(),
                sequence: 12,
                projected_at: None,
            })
        );
        for request in [
            TaskWatchRequest {
                resume_epoch: Some("epoch:watch".to_owned()),
                resume_sequence: None,
            },
            TaskWatchRequest {
                resume_epoch: None,
                resume_sequence: Some(12),
            },
        ] {
            assert!(matches!(
                task_watch_resume_after(request),
                Err(ClientTaskWatchError::InvalidResumePair)
            ));
        }
    }

    #[test]
    fn task_watch_open_seam_authorizes_once_and_dispatches_complete_session_request() {
        use std::cell::RefCell;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:watch",
            "session:watch",
            "local.task.read",
            ClientSurface::Tui,
            now,
        );
        let calls = Cell::new(0_u64);
        let captured = RefCell::new(None);
        let opened = block_on_ready(open_task_watch_via(
            &kernel,
            TaskWatchRequest {
                resume_epoch: Some("epoch:resume".to_owned()),
                resume_sequence: Some(44),
            },
            now,
            |request| {
                calls.set(calls.get() + 1);
                captured.replace(Some(request));
                std::future::ready(Ok("opened"))
            },
        ))
        .unwrap();
        assert_eq!(opened, "opened");
        assert_eq!(calls.get(), 1);
        let request = captured.borrow_mut().take().unwrap();
        let client = request.client.unwrap();
        assert!(!client.request_id.is_empty());
        assert_eq!(client.client_instance_id, "client:context-revoke");
        assert_eq!(client.surface, ClientSurface::Tui as i32);
        assert_eq!(client.session_id, "session:watch");
        assert_eq!(client.api_contract_ref, Some(api_contract_ref()));
        assert!(client.correlation_id.is_none());
        assert_eq!(
            request.resume_after,
            Some(ProjectionPosition {
                epoch: "epoch:resume".to_owned(),
                sequence: 44,
                projected_at: None,
            })
        );
        assert!(request.task_ids.is_empty());
        assert!(request.status_filter.is_empty());

        let denied = authenticated_kernel_for_surface(
            "founder:watch",
            "session:watch-denied",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let denied_calls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(open_task_watch_via(
                &denied,
                TaskWatchRequest::default(),
                now,
                |_request| {
                    denied_calls.set(denied_calls.get() + 1);
                    std::future::ready(Ok(()))
                },
            )),
            Err(ClientTaskWatchError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.task.read"
        ));
        assert_eq!(denied_calls.get(), 0);
    }

    #[test]
    fn attachment_keeps_surface_in_the_shared_kernel_boundary() {
        let kernel =
            ClientKernel::new("egopulse-test", ClientSurface::Tui).expect("valid client kernel");
        assert_eq!(kernel.surface(), ClientSurface::Tui);
    }

    #[test]
    fn task_digest_covers_apply_founder_verdict_with_authority_compatible_metadata_clearing() {
        let mut command = TaskCommand {
            command: Some(task_command::Command::ApplyFounderVerdict(
                egopulse_domain_contracts::v01::egopulse::task::v1::ApplyFounderVerdictCommand {
                    meta: Some(command_metadata("correlation", "client/task-apply")),
                    task_id: "task-1".to_owned(),
                    expected_revision: 7,
                    work_revision: 2,
                    founder_verdict_id: "founder-verdict-1".to_owned(),
                },
            )),
        };
        let expected = canonical_task_digest(&command);
        set_task_digest(&mut command);
        let actual = match command.command.as_ref().expect("command") {
            task_command::Command::ApplyFounderVerdict(value) => value
                .meta
                .as_ref()
                .expect("metadata")
                .request_digest_sha256
                .clone(),
            _ => unreachable!(),
        };
        assert_eq!(actual, expected);
        assert_eq!(canonical_task_digest(&command), expected);
    }

    #[test]
    fn context_revoke_prepare_matches_fixed_canonical_and_protobuf_oracles() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let input = context_revoke_input();
        let canonical_bytes = ContextRevokeSemanticRequest {
            founder_principal_id: "founder:alice",
            snapshot_id: &input.snapshot_id,
            expected_state_revision: input.expected_state_revision,
            reason_code: &input.reason_code,
            evidence_refs: &input.evidence_refs,
            confirmation_proof_ref: &input.confirmation_proof_ref,
        }
        .canonical_bytes();
        assert_eq!(
            hex::encode(canonical_bytes),
            FIXED_CONTEXT_REVOKE_CANONICAL_HEX
        );

        let prepared =
            prepare_context_revoke_with_kernel(&kernel, input).expect("prepare Context revoke");

        assert_eq!(prepared.snapshot_id(), "ctx:001");
        assert_eq!(prepared.expected_state_revision(), 2);
        assert_eq!(prepared.evidence_count(), 2);
        assert_eq!(
            prepared.request_digest_sha256(),
            FIXED_CONTEXT_REVOKE_DIGEST
        );
        let request =
            build_context_revoke_request(&kernel, &prepared, FIXED_CONTEXT_REVOKE_DIGEST, now)
                .expect("build Context revoke request");
        assert_eq!(
            hex::encode(normalized_context_revoke_mutation_bytes(request)),
            FIXED_CONTEXT_REVOKE_MUTATION_HEX
        );
    }

    #[test]
    fn context_revoke_cli_and_tui_share_identical_semantic_command_bytes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let cli_kernel = authenticated_kernel_for_surface(
            "founder:alice",
            "session:context-revoke:surface",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let tui_kernel = authenticated_kernel_for_surface(
            "founder:alice",
            "session:context-revoke:surface",
            "local.context.revoke",
            ClientSurface::Tui,
            now,
        );
        let cli_prepared = prepare_context_revoke_with_kernel(&cli_kernel, context_revoke_input())
            .expect("prepare CLI Context revoke");
        let tui_prepared = prepare_context_revoke_with_kernel(&tui_kernel, context_revoke_input())
            .expect("prepare TUI Context revoke");
        let cli_request = build_context_revoke_request(
            &cli_kernel,
            &cli_prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
        )
        .expect("build CLI Context revoke request");
        let tui_request = build_context_revoke_request(
            &tui_kernel,
            &tui_prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
        )
        .expect("build TUI Context revoke request");

        let cli_client = cli_request.client.as_ref().expect("CLI client metadata");
        let tui_client = tui_request.client.as_ref().expect("TUI client metadata");
        assert_eq!(cli_client.surface, ClientSurface::Cli as i32);
        assert_eq!(tui_client.surface, ClientSurface::Tui as i32);
        assert_ne!(cli_client.request_id, tui_client.request_id);

        let cli_semantic_bytes = normalized_context_revoke_mutation_bytes(cli_request);
        let tui_semantic_bytes = normalized_context_revoke_mutation_bytes(tui_request);
        assert_eq!(cli_semantic_bytes, tui_semantic_bytes);
        assert_eq!(
            hex::encode(cli_semantic_bytes),
            FIXED_CONTEXT_REVOKE_MUTATION_HEX
        );
    }

    #[test]
    fn context_revoke_permission_denial_happens_during_prepare() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:denied",
            "local.task.read",
            now,
        );

        assert!(matches!(
            prepare_context_revoke_with_kernel(&kernel, context_revoke_input()),
            Err(ClientContextRevokeError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.context.revoke"
        ));
    }

    #[test]
    fn context_revoke_invalid_confirmation_never_calls_transport() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let transport_calls = Cell::new(0_u64);

        for supplied_digest in [
            String::new(),
            FIXED_CONTEXT_REVOKE_DIGEST[..63].to_owned(),
            format!("{FIXED_CONTEXT_REVOKE_DIGEST}0"),
            format!(" {FIXED_CONTEXT_REVOKE_DIGEST}"),
            format!("{FIXED_CONTEXT_REVOKE_DIGEST} "),
            FIXED_CONTEXT_REVOKE_DIGEST.to_uppercase(),
            "a".repeat(64),
        ] {
            let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
                .expect("prepare Context revoke");
            let result = block_on_ready(execute_context_revoke_via(
                &kernel,
                prepared,
                &supplied_digest,
                now,
                |_request| {
                    transport_calls.set(transport_calls.get() + 1);
                    std::future::ready(Err("transport must not run".to_owned()))
                },
            ));
            assert!(matches!(
                result,
                Err(ClientContextRevokeError::InvalidConfirmation)
            ));
        }
        assert_eq!(transport_calls.get(), 0);
    }

    #[test]
    fn context_revoke_prepare_is_bound_to_session_and_principal_without_rpc() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let preparation_kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let transport_calls = Cell::new(0_u64);

        for execution_kernel in [
            authenticated_kernel(
                "founder:alice",
                "session:context-revoke:2",
                "local.context.revoke",
                now,
            ),
            authenticated_kernel(
                "founder:bob",
                "session:context-revoke:1",
                "local.context.revoke",
                now,
            ),
        ] {
            let prepared =
                prepare_context_revoke_with_kernel(&preparation_kernel, context_revoke_input())
                    .expect("prepare Context revoke");
            let result = block_on_ready(execute_context_revoke_via(
                &execution_kernel,
                prepared,
                FIXED_CONTEXT_REVOKE_DIGEST,
                now,
                |_request| {
                    transport_calls.set(transport_calls.get() + 1);
                    std::future::ready(Err("transport must not run".to_owned()))
                },
            ));
            assert!(matches!(
                result,
                Err(ClientContextRevokeError::SessionChanged)
            ));
        }
        assert_eq!(transport_calls.get(), 0);
    }

    #[test]
    fn context_revoke_execute_preserves_semantics_idempotency_and_sanitized_receipt() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
            .expect("prepare Context revoke");
        let transport_calls = Cell::new(0_u64);

        let receipt = block_on_ready(execute_context_revoke_via(
            &kernel,
            prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
            |request| {
                transport_calls.set(transport_calls.get() + 1);
                let client = request.client.expect("client metadata");
                assert_eq!(client.session_id, "session:context-revoke:1");
                let context_mutation_command::Command::RevokeContextSnapshot(command) = request
                    .command
                    .and_then(|command| command.command)
                    .expect("Context mutation command");
                let metadata = command.metadata.expect("command metadata");
                assert_eq!(metadata.idempotency_key, "idempotency:context-revoke:1");
                assert_eq!(metadata.idempotency_scope, CONTEXT_REVOKE_IDEMPOTENCY_SCOPE);
                assert_eq!(metadata.request_digest_sha256, FIXED_CONTEXT_REVOKE_DIGEST);
                assert_eq!(command.snapshot_id, "ctx:001");
                assert_eq!(command.expected_state_revision, 2);
                assert_eq!(command.reason_code, "withdrawn");
                assert_eq!(command.evidence_refs, ["evidence:1", "evidence:2"]);
                assert_eq!(command.confirmation_proof_ref, "proof:local:1");
                std::future::ready(Ok(ExecuteContextMutationResponse {
                    outcome: Some(execute_context_mutation_response::Outcome::AuthorityResult(
                        success_context_revoke_receipt(),
                    )),
                }))
            },
        ))
        .expect("execute Context revoke");

        assert_eq!(transport_calls.get(), 1);
        assert_eq!(receipt, success_context_revoke_receipt());
    }

    #[test]
    fn context_revoke_response_errors_and_missing_outcomes_remain_typed() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let api_error = LocalApiError {
            code: LocalApiErrorCode::StateRevisionConflict as i32,
            safe_fingerprint: "context-revoke/cas-conflict/v1".to_owned(),
            retryable: false,
            required_action_code: Some("refresh-context-state".to_owned()),
            current_position: None,
            correlation_id: "correlation:context-revoke".to_owned(),
        };
        let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
            .expect("prepare Context revoke");
        let result = block_on_ready(execute_context_revoke_via(
            &kernel,
            prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
            |_request| {
                std::future::ready(Ok(ExecuteContextMutationResponse {
                    outcome: Some(execute_context_mutation_response::Outcome::Error(
                        api_error.clone(),
                    )),
                }))
            },
        ));
        assert!(matches!(
            result,
            Err(ClientContextRevokeError::Api(error)) if *error == api_error
        ));

        let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
            .expect("prepare Context revoke");
        let result = block_on_ready(execute_context_revoke_via(
            &kernel,
            prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
            |_request| std::future::ready(Ok(ExecuteContextMutationResponse { outcome: None })),
        ));
        assert!(matches!(
            result,
            Err(ClientContextRevokeError::MalformedResponse(
                "outcome missing"
            ))
        ));
    }

    #[test]
    fn approval_baseline_is_complete_actionable_sorted_and_capped() {
        let position = approval_position(7);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let (actual_position, approvals) = compile_approval_baseline(vec![
            approval_page(
                &position,
                vec![
                    approval_view("approval:z", &position, Some(decide)),
                    approval_view("approval:closed", &position, None),
                ],
                Some("cursor:2"),
            ),
            approval_page(
                &position,
                vec![approval_view("approval:a", &position, Some(decide))],
                None,
            ),
        ])
        .expect("complete approval baseline");
        assert_eq!(actual_position, position);
        assert_eq!(
            approvals.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approval:a", "approval:z"]
        );

        let global_position = approval_position(9);
        let newer_view_position = approval_position(8);
        let older_view_position = approval_position(7);
        let (actual_position, approvals) = compile_approval_baseline(vec![approval_page(
            &global_position,
            vec![
                approval_view("approval:newer", &newer_view_position, Some(decide)),
                approval_view("approval:older", &older_view_position, Some(decide)),
            ],
            None,
        )])
        .expect("unrelated projections may advance the global page position");
        assert_eq!(actual_position, global_position);
        assert_eq!(
            approvals["approval:newer"]
                .view()
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.position.as_ref()),
            Some(&newer_view_position)
        );
        assert_eq!(
            approvals["approval:older"]
                .view()
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.position.as_ref()),
            Some(&older_view_position)
        );

        let ahead_position = approval_position(global_position.sequence + 1);
        assert!(matches!(
            compile_approval_baseline(vec![approval_page(
                &global_position,
                vec![approval_view(
                    "approval:ahead",
                    &ahead_position,
                    Some(decide),
                )],
                None,
            )]),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline view position is outside the page snapshot"
            ))
        ));

        let mut foreign_epoch_position = older_view_position.clone();
        foreign_epoch_position.epoch = "epoch:foreign-approval-watch".to_owned();
        assert!(matches!(
            compile_approval_baseline(vec![approval_page(
                &global_position,
                vec![approval_view(
                    "approval:foreign-epoch",
                    &foreign_epoch_position,
                    Some(decide),
                )],
                None,
            )]),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline view position is outside the page snapshot"
            ))
        ));

        let views: Vec<_> = (0..=APPROVAL_WATCH_BASELINE_MAX_VIEWS)
            .map(|index| approval_view(format!("approval:{index:04}"), &position, Some(decide)))
            .collect();
        let pages = views
            .chunks(APPROVAL_WATCH_BASELINE_PAGE_SIZE as usize)
            .enumerate()
            .map(|(index, chunk)| {
                let next = (index + 1
                    < views
                        .len()
                        .div_ceil(APPROVAL_WATCH_BASELINE_PAGE_SIZE as usize))
                .then(|| format!("cursor:{}", index + 1));
                approval_page(&position, chunk.to_vec(), next.as_deref())
            })
            .collect();
        assert!(matches!(
            compile_approval_baseline(pages),
            Err(ClientApprovalWatchError::BaselineLimitExceeded)
        ));
    }

    #[test]
    fn guided_approval_requires_the_exact_reviewed_safe_summary_before_allow_once() {
        use std::cell::Cell;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(13_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:summary",
            "session:summary",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        for case in 0..6 {
            let mut input = guided_approval_input(GuidedApprovalDecision::AllowOnce);
            let mut view = approval_view(
                "approval:guided:1",
                &approval_position(12),
                Some(AvailableActionKind::DecideHarnessApproval as i32),
            );
            match case {
                0 => view.display_summary = None,
                1 => input.reviewed_summary_digest_sha256 = None,
                2 => input.reviewed_summary_digest_sha256 = Some("d".repeat(64)),
                3 => {
                    view.display_summary
                        .as_mut()
                        .expect("summary")
                        .command_preview = "cargo clean".to_owned()
                }
                4 => {
                    let mut summary = view.display_summary.take().expect("summary");
                    summary.command_preview = "cargo clean".to_owned();
                    view.display_summary = Some(
                        egopulse_domain_contracts::approval_display::seal_approval_display_summary(
                            summary,
                        ),
                    );
                }
                _ => view.action_digest_sha256 = "e".repeat(64),
            }
            let sends = Cell::new(0);
            let result = block_on_ready(decide_guided_approval_via(
                &kernel,
                input,
                now,
                |_| {
                    std::future::ready(Ok(GetHarnessApprovalViewResponse {
                        outcome: Some(get_harness_approval_view_response::Outcome::View(view)),
                    }))
                },
                |_| {
                    sends.set(sends.get() + 1);
                    std::future::ready(Ok(guided_approval_response(
                        GuidedApprovalDecision::AllowOnce,
                        false,
                        None,
                    )))
                },
            ));
            assert!(
                matches!(
                    result,
                    Err(ClientGuidedApprovalDecisionError::InvalidInput(_))
                ),
                "case {case}"
            );
            assert_eq!(sends.get(), 0);
        }
        let mut legacy = approval_view(
            "approval:guided:1",
            &approval_position(12),
            Some(AvailableActionKind::DecideHarnessApproval as i32),
        );
        legacy.display_summary = None;
        let denied = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(legacy)),
                }))
            },
            |_| {
                std::future::ready(Ok(guided_approval_response(
                    GuidedApprovalDecision::Deny,
                    false,
                    None,
                )))
            },
        ));
        assert!(
            denied.is_ok(),
            "legacy requests must still be safely deniable"
        );
    }

    #[test]
    fn guided_approval_reads_latest_view_and_seals_all_three_decisions() {
        use std::cell::RefCell;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(13_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-approval",
            "session:guided-approval",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(12);
        for (decision, replayed) in [
            (GuidedApprovalDecision::AllowOnce, false),
            (GuidedApprovalDecision::Deny, false),
            (GuidedApprovalDecision::CancelAttempt, true),
        ] {
            let get_request = RefCell::new(None);
            let decide_request = RefCell::new(None);
            let warning = (decision == GuidedApprovalDecision::CancelAttempt)
                .then(|| local_api_error(LocalApiErrorCode::ProjectionBehind));
            let result = block_on_ready(decide_guided_approval_via(
                &kernel,
                guided_approval_input(decision),
                now,
                |request| {
                    get_request.replace(Some(request));
                    std::future::ready(Ok(GetHarnessApprovalViewResponse {
                        outcome: Some(get_harness_approval_view_response::Outcome::View(
                            approval_view(
                                "approval:guided:1",
                                &position,
                                Some(AvailableActionKind::DecideHarnessApproval as i32),
                            ),
                        )),
                    }))
                },
                |request| {
                    decide_request.replace(Some(request));
                    std::future::ready(Ok(guided_approval_response(
                        decision,
                        replayed,
                        warning.clone(),
                    )))
                },
            ))
            .expect("guided approval decision");
            assert!(result.committed());
            assert_eq!(result.replayed(), replayed);
            assert_eq!(result.decision(), decision);
            assert_eq!(result.authority_decision_ref(), "policy-decision:guided:1");
            assert_eq!(result.projection_warning(), warning.as_ref());

            let get = get_request.into_inner().expect("Get request");
            assert_eq!(get.approval_request_id, "approval:guided:1");
            assert!(get.minimum_position.is_none());
            let request = decide_request.into_inner().expect("Decide request");
            let client = request.client.expect("command client metadata");
            assert_eq!(client.session_id, "session:guided-approval");
            assert_eq!(
                client.correlation_id.as_deref(),
                Some(result.correlation_id())
            );
            let command = request.command.expect("sealed approval command");
            assert_eq!(command.approval_request_id, "approval:guided:1");
            assert_eq!(command.expected_action_digest_sha256, "b".repeat(64));
            assert_eq!(
                command.expected_request_observation_id,
                "observation:approval:guided:1"
            );
            assert_eq!(command.expected_request_observation_sequence, 1);
            assert_eq!(command.expected_request_revision, 1);
            assert_eq!(command.decision, decision.wire_value());
            assert_eq!(command.reason_code, "  founder-reviewed  ");
            assert_eq!(
                command.confirmation_proof_ref.as_deref(),
                Some("proof:approval:1")
            );
            let sealed_digest = command
                .metadata
                .as_ref()
                .expect("command metadata")
                .request_digest_sha256
                .clone();
            assert!(is_canonical_sha256(&sealed_digest));
            let mut wrapped = PolicyDecisionCommand {
                command: Some(
                    policy_decision_command::Command::IssueHarnessApprovalDecision(command),
                ),
            };
            set_policy_digest(&mut wrapped);
            let policy_decision_command::Command::IssueHarnessApprovalDecision(recomputed) =
                wrapped.command.expect("issue command")
            else {
                unreachable!("test command branch")
            };
            assert_eq!(
                recomputed
                    .metadata
                    .expect("recomputed metadata")
                    .request_digest_sha256,
                sealed_digest
            );
        }
    }

    #[test]
    fn guided_approval_uses_stable_idempotency_and_semantic_digest() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(13_500);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-idempotency",
            "session:guided-idempotency",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(13);
        let base = guided_approval_input(GuidedApprovalDecision::AllowOnce);
        let first = sealed_guided_approval_command(&kernel, &position, base.clone(), now);
        let replay = sealed_guided_approval_command(
            &kernel,
            &position,
            base.clone(),
            now + Duration::from_secs(1),
        );
        let changed_decision = sealed_guided_approval_command(
            &kernel,
            &position,
            GuidedApprovalDecisionInput {
                decision: GuidedApprovalDecision::Deny,
                ..base.clone()
            },
            now + Duration::from_secs(2),
        );
        let changed_reason = sealed_guided_approval_command(
            &kernel,
            &position,
            GuidedApprovalDecisionInput {
                reason_code: "founder-reconsidered".to_owned(),
                ..base
            },
            now + Duration::from_secs(3),
        );

        fn metadata(command: &IssueHarnessApprovalDecisionCommand) -> &CommandMetadata {
            command.metadata.as_ref().expect("command metadata")
        }
        assert_eq!(
            metadata(&first).idempotency_key,
            guided_approval_idempotency_key("approval:guided:1")
        );
        assert_eq!(
            metadata(&first).idempotency_key,
            metadata(&replay).idempotency_key
        );
        assert_eq!(
            metadata(&first).request_digest_sha256,
            metadata(&replay).request_digest_sha256
        );
        assert_ne!(metadata(&first).command_id, metadata(&replay).command_id);
        for changed in [&changed_decision, &changed_reason] {
            assert_eq!(
                metadata(&first).idempotency_key,
                metadata(changed).idempotency_key
            );
            assert_ne!(
                metadata(&first).request_digest_sha256,
                metadata(changed).request_digest_sha256
            );
        }
    }

    #[test]
    fn guided_approval_preflights_both_permissions_and_input_before_rpc() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(14_000);
        for permissions in [&["local.approval.read"][..], &["local.approval.decide"][..]] {
            let kernel = authenticated_kernel_with_permissions(
                "founder:guided-denied",
                "session:guided-denied",
                permissions,
                ClientSurface::Cli,
                now,
            );
            let gets = Cell::new(0_u64);
            let decisions = Cell::new(0_u64);
            let result = block_on_ready(decide_guided_approval_via(
                &kernel,
                guided_approval_input(GuidedApprovalDecision::Deny),
                now,
                |_request| {
                    gets.set(gets.get() + 1);
                    std::future::ready(Err("must-not-get".to_owned()))
                },
                |_request| {
                    decisions.set(decisions.get() + 1);
                    std::future::ready(Err("must-not-decide".to_owned()))
                },
            ));
            assert!(matches!(
                result,
                Err(ClientGuidedApprovalDecisionError::Kernel(
                    KernelError::PermissionDenied(_)
                ))
            ));
            assert_eq!(gets.get(), 0);
            assert_eq!(decisions.get(), 0);
        }

        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-invalid",
            "session:guided-invalid",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        for input in [
            GuidedApprovalDecisionInput {
                approval_request_id: " \t ".to_owned(),
                ..guided_approval_input(GuidedApprovalDecision::AllowOnce)
            },
            GuidedApprovalDecisionInput {
                reason_code: " \t ".to_owned(),
                ..guided_approval_input(GuidedApprovalDecision::AllowOnce)
            },
            GuidedApprovalDecisionInput {
                confirmation_proof_ref: Some("  ".to_owned()),
                ..guided_approval_input(GuidedApprovalDecision::AllowOnce)
            },
        ] {
            let gets = Cell::new(0_u64);
            let decisions = Cell::new(0_u64);
            assert!(matches!(
                block_on_ready(decide_guided_approval_via(
                    &kernel,
                    input,
                    now,
                    |_request| {
                        gets.set(gets.get() + 1);
                        std::future::ready(Err("must-not-get".to_owned()))
                    },
                    |_request| {
                        decisions.set(decisions.get() + 1);
                        std::future::ready(Err("must-not-decide".to_owned()))
                    },
                )),
                Err(ClientGuidedApprovalDecisionError::InvalidInput(_))
            ));
            assert_eq!(gets.get(), 0);
            assert_eq!(decisions.get(), 0);
        }
    }

    #[test]
    fn guided_approval_rejects_missing_non_actionable_and_mismatched_latest_views() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(15_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-view",
            "session:guided-view",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(15);
        let decisions = Cell::new(0_u64);
        let not_found = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::Error(
                        local_api_error(LocalApiErrorCode::NotFound),
                    )),
                }))
            },
            |_request| {
                decisions.set(decisions.get() + 1);
                std::future::ready(Err("must-not-decide".to_owned()))
            },
        ));
        assert!(matches!(
            not_found,
            Err(ClientGuidedApprovalDecisionError::NotFound)
        ));

        let non_actionable = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(
                        approval_view("approval:guided:1", &position, None),
                    )),
                }))
            },
            |_request| {
                decisions.set(decisions.get() + 1);
                std::future::ready(Err("must-not-decide".to_owned()))
            },
        ));
        assert!(matches!(
            non_actionable,
            Err(ClientGuidedApprovalDecisionError::NonActionable)
        ));

        let mismatch = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(
                        approval_view(
                            "approval:different",
                            &position,
                            Some(AvailableActionKind::DecideHarnessApproval as i32),
                        ),
                    )),
                }))
            },
            |_request| {
                decisions.set(decisions.get() + 1);
                std::future::ready(Err("must-not-decide".to_owned()))
            },
        ));
        assert!(matches!(
            mismatch,
            Err(ClientGuidedApprovalDecisionError::Protocol(
                "approval view binding invalid"
            ))
        ));
        assert_eq!(decisions.get(), 0);
    }

    #[test]
    #[allow(deprecated)]
    fn guided_approval_preserves_api_authority_transport_and_protocol_failures() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(16_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-failures",
            "session:guided-failures",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(16);
        let latest = || GetHarnessApprovalViewResponse {
            outcome: Some(get_harness_approval_view_response::Outcome::View(
                approval_view(
                    "approval:guided:1",
                    &position,
                    Some(AvailableActionKind::DecideHarnessApproval as i32),
                ),
            )),
        };

        let api = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::Error(
                        local_api_error(LocalApiErrorCode::ProjectionBehind),
                    )),
                }))
            },
            |_request| std::future::ready(Err("must-not-decide".to_owned())),
        ));
        assert!(matches!(
            api,
            Err(ClientGuidedApprovalDecisionError::Api(_))
        ));

        let get_transport = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Err("get-status".to_owned())),
            |_request| std::future::ready(Err("must-not-decide".to_owned())),
        ));
        assert!(matches!(
            get_transport,
            Err(ClientGuidedApprovalDecisionError::Transport(detail)) if detail == "get-status"
        ));

        let decide_transport = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| std::future::ready(Err("decide-status".to_owned())),
        ));
        assert!(matches!(
            decide_transport,
            Err(ClientGuidedApprovalDecisionError::Transport(detail)) if detail == "decide-status"
        ));

        let mut authority_failure =
            guided_approval_response(GuidedApprovalDecision::AllowOnce, false, None);
        let authority = authority_failure
            .sanitized_authority_result
            .as_mut()
            .expect("sanitized result");
        authority.committed = false;
        authority.error_code = PolicyDecisionErrorCode::RevisionConflict as i32;
        authority.safe_error_fingerprint = Some("approval/revision-conflict/v1".to_owned());
        let authority = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| std::future::ready(Ok(authority_failure)),
        ));
        assert!(matches!(
            authority,
            Err(ClientGuidedApprovalDecisionError::Authority {
                error_code,
                ..
            }) if error_code == PolicyDecisionErrorCode::RevisionConflict as i32
        ));

        let protocol = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| {
                std::future::ready(Ok(DecideHarnessApprovalResponse {
                    await_token: None,
                    gateway_error: None,
                    policy_authority_result: None,
                    sanitized_authority_result: None,
                }))
            },
        ));
        assert!(matches!(
            protocol,
            Err(ClientGuidedApprovalDecisionError::Protocol(
                "sanitized approval result missing"
            ))
        ));

        let mut wrong_state =
            guided_approval_response(GuidedApprovalDecision::AllowOnce, false, None);
        wrong_state
            .sanitized_authority_result
            .as_mut()
            .expect("sanitized result")
            .state = HarnessApprovalDecisionStateKind::Revoked as i32;
        let wrong_state = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| std::future::ready(Ok(wrong_state)),
        ));
        assert!(matches!(
            wrong_state,
            Err(ClientGuidedApprovalDecisionError::Protocol(
                "sanitized approval result invalid"
            ))
        ));
    }

    #[test]
    fn approval_baseline_rejects_position_cursor_and_identity_drift() {
        let position = approval_position(7);
        let other_position = approval_position(8);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let valid = || approval_view("approval:1", &position, Some(decide));

        let cases = [
            vec![
                approval_page(&position, vec![valid()], Some("cursor:2")),
                approval_page(
                    &other_position,
                    vec![approval_view("approval:2", &other_position, Some(decide))],
                    None,
                ),
            ],
            vec![approval_page(&position, Vec::new(), Some("cursor:2"))],
            vec![
                approval_page(&position, vec![valid()], Some("cursor:same")),
                approval_page(
                    &position,
                    vec![approval_view("approval:2", &position, Some(decide))],
                    Some("cursor:same"),
                ),
            ],
            vec![approval_page(
                &position,
                vec![
                    valid(),
                    approval_view("approval:1", &position, Some(decide)),
                ],
                None,
            )],
            vec![approval_page(
                &position,
                vec![approval_view("", &position, Some(decide))],
                None,
            )],
        ];
        for pages in cases {
            assert!(compile_approval_baseline(pages).is_err());
        }

        let unknown_action = approval_view("approval:unknown", &position, Some(i32::MAX));
        assert!(matches!(
            compile_approval_baseline(vec![approval_page(&position, vec![unknown_action], None,)]),
            Err(ClientApprovalWatchError::Protocol(
                "approval action kind is unknown"
            ))
        ));
    }

    #[test]
    fn approval_baseline_read_seam_authorizes_once_and_follows_the_cursor_chain() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(11_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:approval-baseline",
            "session:approval-baseline",
            "local.approval.read",
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(100);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let mut replies = VecDeque::from([
            Ok(approval_page(
                &position,
                vec![approval_view("approval:b", &position, Some(decide))],
                Some("cursor:2"),
            )),
            Ok(approval_page(
                &position,
                vec![approval_view("approval:a", &position, Some(decide))],
                None,
            )),
        ]);
        let mut requests = Vec::new();
        let baseline = block_on_ready(read_actionable_approval_queue_via(
            &kernel,
            now,
            |request| {
                requests.push(request);
                std::future::ready(replies.pop_front().expect("scripted page"))
            },
        ))
        .expect("complete production pagination seam");
        assert!(replies.is_empty());
        assert_eq!(baseline.position(), &position);
        assert_eq!(
            baseline
                .actionable_approvals()
                .into_iter()
                .map(ActionableApproval::approval_request_id)
                .collect::<Vec<_>>(),
            ["approval:a", "approval:b"]
        );
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].page_cursor, None);
        assert_eq!(requests[1].page_cursor.as_deref(), Some("cursor:2"));
        for request in &requests {
            assert!(request.actionable_only);
            assert_eq!(request.page_size, 100);
            assert!(request.minimum_position.is_none());
            assert!(request.task_ids.is_empty());
        }
        assert_eq!(requests[0].client, requests[1].client);
        let metadata = requests[0].client.as_ref().expect("session metadata");
        assert_eq!(metadata.session_id, "session:approval-baseline");
        assert_eq!(metadata.surface, ClientSurface::Cli as i32);

        let denied = authenticated_kernel_for_surface(
            "founder:approval-baseline",
            "session:approval-baseline-denied",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let dispatches = Cell::new(0_u64);
        let denied = block_on_ready(read_actionable_approval_queue_via(
            &denied,
            now,
            |_request| {
                dispatches.set(dispatches.get() + 1);
                std::future::ready(Err("must-not-dispatch".to_owned()))
            },
        ));
        assert!(matches!(
            denied,
            Err(ClientApprovalWatchError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.approval.read"
        ));
        assert_eq!(dispatches.get(), 0);
    }

    #[test]
    fn approval_baseline_read_seam_fails_atomically_for_remote_and_pagination_drift() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(12_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:approval-baseline-failure",
            "session:approval-baseline-failure",
            "local.approval.read",
            ClientSurface::Tui,
            now,
        );
        let position = approval_position(100);
        let other_position = approval_position(101);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let one = || approval_view("approval:1", &position, Some(decide));

        let mut position_drift = VecDeque::from([
            Ok(approval_page(&position, vec![one()], Some("cursor:2"))),
            Ok(approval_page(
                &other_position,
                vec![approval_view("approval:2", &other_position, Some(decide))],
                None,
            )),
        ]);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| std::future::ready(
                    position_drift.pop_front().expect("position drift page")
                ),
            )),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline position changed across pages"
            ))
        ));

        let mut repeated_cursor = VecDeque::from([
            Ok(approval_page(&position, vec![one()], Some("cursor:same"))),
            Ok(approval_page(
                &position,
                vec![approval_view("approval:2", &position, Some(decide))],
                Some("cursor:same"),
            )),
        ]);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| std::future::ready(
                    repeated_cursor.pop_front().expect("repeated cursor page")
                ),
            )),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline cursor did not advance"
            ))
        ));

        let mut empty_with_cursor = VecDeque::from([Ok(approval_page(
            &position,
            Vec::new(),
            Some("cursor:next"),
        ))]);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| std::future::ready(
                    empty_with_cursor.pop_front().expect("empty cursor page")
                ),
            )),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline cursor did not advance"
            ))
        ));

        let mut oversized_pages = VecDeque::new();
        for page_index in 0..=10 {
            let item_count = if page_index == 10 { 1 } else { 100 };
            let views = (0..item_count)
                .map(|item_index| {
                    approval_view(
                        format!("approval:{page_index:02}:{item_index:03}"),
                        &position,
                        Some(decide),
                    )
                })
                .collect();
            let next = (page_index < 10).then(|| format!("cursor:{}", page_index + 1));
            oversized_pages.push_back(Ok(approval_page(&position, views, next.as_deref())));
        }
        let oversized_dispatches = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| {
                    oversized_dispatches.set(oversized_dispatches.get() + 1);
                    std::future::ready(oversized_pages.pop_front().expect("oversized page"))
                },
            )),
            Err(ClientApprovalWatchError::BaselineLimitExceeded)
        ));
        assert_eq!(oversized_dispatches.get(), 11);

        let api_error = LocalApiError {
            code: LocalApiErrorCode::StateRevisionConflict as i32,
            safe_fingerprint: "approval-baseline/unavailable/v1".to_owned(),
            retryable: true,
            required_action_code: Some("retry-read".to_owned()),
            current_position: None,
            correlation_id: "correlation:approval-baseline".to_owned(),
        };
        let api_dispatches = Cell::new(0_u64);
        let api_result = block_on_ready(read_actionable_approval_queue_via(
            &kernel,
            now,
            |_request| {
                api_dispatches.set(api_dispatches.get() + 1);
                std::future::ready(Ok(ListHarnessApprovalViewsResponse {
                    views: vec![one()],
                    next_page_cursor: None,
                    snapshot_position: Some(position.clone()),
                    error: Some(api_error.clone()),
                }))
            },
        ));
        assert!(matches!(api_result, Err(ClientApprovalWatchError::Api(_))));
        assert_eq!(api_dispatches.get(), 1);

        let transport_dispatches = Cell::new(0_u64);
        let transport = block_on_ready(read_actionable_approval_queue_via(
            &kernel,
            now,
            |_request| {
                transport_dispatches.set(transport_dispatches.get() + 1);
                std::future::ready(Err("tonic-status".to_owned()))
            },
        ));
        assert!(matches!(
            transport,
            Err(ClientApprovalWatchError::Transport(detail)) if detail == "tonic-status"
        ));
        assert_eq!(transport_dispatches.get(), 1);
    }

    #[test]
    fn approval_watch_wire_requests_freeze_baseline_and_live_filters() {
        let metadata = ClientRequestMetadata {
            client_instance_id: "client:approval-watch".to_owned(),
            surface: ClientSurface::Cli as i32,
            session_id: "session:approval-watch".to_owned(),
            request_id: "request:approval-watch".to_owned(),
            api_contract_ref: Some(api_contract_ref()),
            correlation_id: None,
        };
        let baseline =
            approval_baseline_wire_request(metadata.clone(), Some("cursor:next".to_owned()));
        assert_eq!(baseline.client, Some(metadata.clone()));
        assert!(baseline.actionable_only);
        assert_eq!(baseline.page_size, 100);
        assert_eq!(baseline.page_cursor.as_deref(), Some("cursor:next"));
        assert!(baseline.minimum_position.is_none());
        assert!(baseline.task_ids.is_empty());
        assert!(baseline.request_lifecycle_filter.is_empty());
        assert!(baseline.decision_state_filter.is_empty());

        let position = approval_position(11);
        let watch = approval_watch_wire_request(metadata.clone(), Some(position.clone()));
        assert_eq!(watch.client, Some(metadata));
        assert_eq!(watch.resume_after, Some(position));
        assert!(!watch.actionable_only);
        assert!(watch.approval_request_ids.is_empty());
        assert!(watch.task_ids.is_empty());
        assert!(watch.request_lifecycle_filter.is_empty());
        assert!(watch.decision_state_filter.is_empty());
    }

    #[test]
    fn approval_watch_open_seam_authorizes_before_stream_dispatch() {
        use std::cell::RefCell;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:approval-watch",
            "session:approval-watch",
            "local.approval.read",
            ClientSurface::Cli,
            now,
        );
        let calls = Cell::new(0_u64);
        let captured = RefCell::new(None);
        let position = approval_position(80);
        let opened = block_on_ready(open_approval_stream_via(
            &kernel,
            Some(position.clone()),
            now,
            |request| {
                calls.set(calls.get() + 1);
                captured.replace(Some(request));
                std::future::ready(Ok("opened"))
            },
        ))
        .expect("authorized approval stream");
        assert_eq!(opened, "opened");
        assert_eq!(calls.get(), 1);
        let request = captured.borrow_mut().take().expect("captured request");
        assert_eq!(request.resume_after, Some(position));
        assert!(!request.actionable_only);
        let client = request.client.expect("session metadata");
        assert_eq!(client.session_id, "session:approval-watch");
        assert_eq!(client.surface, ClientSurface::Cli as i32);
        assert_eq!(client.api_contract_ref, Some(api_contract_ref()));

        let denied = authenticated_kernel_for_surface(
            "founder:approval-watch",
            "session:approval-watch-denied",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let denied_calls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(open_approval_stream_via(&denied, None, now, |_request| {
                denied_calls.set(denied_calls.get() + 1);
                std::future::ready(Ok(()))
            })),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.approval.read"
        ));
        assert_eq!(denied_calls.get(), 0);
    }

    #[test]
    fn approval_watch_applied_upserts_and_removes_without_fake_remove() {
        let position = approval_position(8);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let original = approval_view("approval:1", &position, Some(decide));
        let mut actionable = BTreeMap::from([(
            original.approval_request_id.clone(),
            ActionableApproval {
                view: original.clone(),
            },
        )]);
        let mut processor = ApprovalWatchProcessor::default();

        let unknown = approval_view("approval:1", &position, Some(i32::MAX));
        let error = processor
            .process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position.clone()),
                snapshot: Some(unknown),
                reset_reason_code: None,
            })
            .and_then(|update| apply_approval_watch_update(&mut actionable, &update));
        assert!(matches!(error, Err(ClientApprovalWatchError::Protocol(_))));
        assert_eq!(actionable["approval:1"].view(), &original);

        let later = approval_position(9);
        let closed = approval_view("approval:1", &later, None);
        let update = processor
            .process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(later),
                snapshot: Some(closed),
                reset_reason_code: None,
            })
            .expect("valid leaving-filter update");
        apply_approval_watch_update(&mut actionable, &update).expect("remove by authoritative id");
        assert!(actionable.is_empty());
        assert_eq!(original.task_id, "task:approval:1");
    }

    #[test]
    fn approval_queue_session_uses_only_its_consumed_baseline_floor() {
        let floor = approval_position(100);
        let mut last_position = floor.clone();
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let current = approval_view("approval:current", &floor, Some(decide));
        let mut actionable = BTreeMap::from([(
            current.approval_request_id.clone(),
            ActionableApproval {
                view: current.clone(),
            },
        )]);

        let old_position = approval_position(80);
        let old = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: old_position.clone(),
            view: Some(approval_view("approval:old", &old_position, Some(decide))),
            reset_reason_code: None,
        };
        assert!(matches!(
            apply_approval_queue_session_update(&mut actionable, &mut last_position, &old),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamOutOfOrder
            ))
        ));
        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable["approval:current"].view(), &current);

        let same_position_applied = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: floor.clone(),
            view: Some(approval_view("approval:same", &floor, Some(decide))),
            reset_reason_code: None,
        };
        apply_approval_queue_session_update(
            &mut actionable,
            &mut last_position,
            &same_position_applied,
        )
        .expect("processor-classified same-position identity is applied");

        let next_position = approval_position(101);
        let next = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: next_position.clone(),
            view: Some(approval_view("approval:next", &next_position, Some(decide))),
            reset_reason_code: None,
        };
        apply_approval_queue_session_update(&mut actionable, &mut last_position, &next)
            .expect("post-baseline update");
        assert_eq!(
            actionable.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approval:current", "approval:next", "approval:same"]
        );

        let other_epoch = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: ProjectionPosition {
                epoch: "epoch:other".to_owned(),
                sequence: 101,
                projected_at: None,
            },
            view: None,
            reset_reason_code: None,
        };
        assert!(matches!(
            apply_approval_queue_session_update(&mut actionable, &mut last_position, &other_epoch,),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamResetMissing
            ))
        ));
        assert_eq!(actionable.len(), 3);

        let back_to_floor = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Replay,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: floor,
            view: Some(current),
            reset_reason_code: None,
        };
        assert!(matches!(
            apply_approval_queue_session_update(
                &mut actionable,
                &mut last_position,
                &back_to_floor,
            ),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamOutOfOrder
            ))
        ));
    }

    #[test]
    fn approval_queue_session_accepts_distinct_same_position_entities_and_rejects_conflicts() {
        let position = approval_position(101);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let mut processor = ApprovalWatchProcessor::default();
        let mut actionable = BTreeMap::new();
        let mut last_position = approval_position(100);

        for approval_request_id in ["approval:101:a", "approval:101:b"] {
            let update = processor
                .process(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Snapshot as i32,
                    position: Some(position.clone()),
                    snapshot: Some(approval_view(approval_request_id, &position, Some(decide))),
                    reset_reason_code: None,
                })
                .expect("distinct same-position approval is valid");
            assert_eq!(update.classification, ApprovalWatchClassification::Applied);
            apply_approval_queue_session_update(&mut actionable, &mut last_position, &update)
                .expect("session trusts processor classification");
        }
        assert_eq!(last_position, position);
        assert_eq!(
            actionable.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approval:101:a", "approval:101:b"]
        );

        let mut conflicting = approval_view("approval:101:a", &position, Some(decide));
        conflicting.action_digest_sha256 = "c".repeat(64);
        assert!(matches!(
            processor.process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position),
                snapshot: Some(conflicting),
                reset_reason_code: None,
            }),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::ConflictingStreamReplay
            ))
        ));
        assert_eq!(actionable.len(), 2);
    }

    #[test]
    fn approval_watch_replay_heartbeat_reset_eof_and_transport_are_non_destructive() {
        let position = approval_position(8);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let original = approval_view("approval:1", &position, Some(decide));
        let mut actionable = BTreeMap::new();
        let mut processor = ApprovalWatchProcessor::default();
        let frame = HarnessApprovalViewStreamFrame {
            kind: StreamFrameKind::Snapshot as i32,
            position: Some(position.clone()),
            snapshot: Some(original.clone()),
            reset_reason_code: None,
        };
        let first = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(Some(frame.clone()))),
        ))
        .expect("first update")
        .expect("frame");
        assert_eq!(first.classification, ApprovalWatchClassification::Applied);
        let replay = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(Some(frame))),
        ))
        .expect("replay")
        .expect("frame");
        assert_eq!(replay.classification, ApprovalWatchClassification::Replay);

        let heartbeat_position = approval_position(9);
        let heartbeat = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || {
                std::future::ready(Ok(Some(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Heartbeat as i32,
                    position: Some(heartbeat_position),
                    snapshot: None,
                    reset_reason_code: None,
                })))
            },
        ))
        .expect("heartbeat")
        .expect("frame");
        assert_eq!(
            heartbeat.classification,
            ApprovalWatchClassification::Heartbeat
        );
        assert_eq!(actionable["approval:1"].view(), &original);

        let eof = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(None)),
        ));
        assert!(matches!(eof, Err(ClientApprovalWatchError::UnexpectedEof)));
        let transport = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Err("tonic-status".to_owned())),
        ));
        assert!(matches!(
            transport,
            Err(ClientApprovalWatchError::Transport(_))
        ));
        assert_eq!(actionable["approval:1"].view(), &original);

        let reset = HarnessApprovalViewStreamFrame {
            kind: StreamFrameKind::ResetRequired as i32,
            position: Some(approval_position(10)),
            snapshot: None,
            reset_reason_code: Some("projection_reset".to_owned()),
        };
        let reset = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(Some(reset))),
        ))
        .expect("reset frame")
        .expect("frame");
        assert_eq!(
            reset.classification,
            ApprovalWatchClassification::ResetRequired
        );
        let polls = Cell::new(0);
        let blocked = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || {
                polls.set(polls.get() + 1);
                std::future::ready(Ok(None))
            },
        ));
        assert!(matches!(
            blocked,
            Err(ClientApprovalWatchError::ResetBarrier)
        ));
        assert_eq!(polls.get(), 0);
        assert_eq!(actionable["approval:1"].view(), &original);
    }

    #[test]
    fn approval_watch_rejects_out_of_order_and_same_position_conflicts() {
        let position = approval_position(101);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let mut processor = ApprovalWatchProcessor::default();
        let mut view = approval_view("approval:1", &position, Some(decide));
        processor
            .process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position.clone()),
                snapshot: Some(view.clone()),
                reset_reason_code: None,
            })
            .expect("first frame");
        view.action_digest_sha256 = "c".repeat(64);
        assert!(matches!(
            processor.process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position),
                snapshot: Some(view),
                reset_reason_code: None,
            }),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::ConflictingStreamReplay
            ))
        ));

        let older = approval_position(100);
        assert!(matches!(
            processor.process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Heartbeat as i32,
                position: Some(older),
                snapshot: None,
                reset_reason_code: None,
            }),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamOutOfOrder
            ))
        ));

        for reason in ["epoch_changed", "cursor_before_retention", "cursor_ahead"] {
            let mut reset_processor = ApprovalWatchProcessor::default();
            let reset = reset_processor
                .process(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::ResetRequired as i32,
                    position: Some(approval_position(102)),
                    snapshot: None,
                    reset_reason_code: Some(reason.to_owned()),
                })
                .expect("well-formed reset barrier");
            assert_eq!(
                reset.classification,
                ApprovalWatchClassification::ResetRequired
            );
            assert!(matches!(
                reset_processor.process(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Heartbeat as i32,
                    position: Some(approval_position(103)),
                    snapshot: None,
                    reset_reason_code: None,
                }),
                Err(ClientApprovalWatchError::ResetBarrier)
            ));
        }
    }

    #[test]
    fn guided_founder_verdict_submits_rework_and_risk_accept_through_revalidated_materials() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            now,
        );
        for selection in [
            GuidedFounderVerdictSelection::Rework,
            GuidedFounderVerdictSelection::Accept,
        ] {
            let review = verdict_review_with_open_items(VerificationConclusion::Partial);
            let coverage = FounderSupportingMaterialCoverage {
                risk_category: if selection == GuidedFounderVerdictSelection::Rework {
                    RiskCategory::Unspecified as i32
                } else {
                    RiskCategory::QualityResidual as i32
                },
                discrepancy_ids: vec!["discrepancy:review:1".into()],
                unverified_item_ids: vec!["unverified:review:1".into()],
            };
            let roles = if selection == GuidedFounderVerdictSelection::Rework {
                vec![FounderSupportingMaterialRole::ReworkRequiredChanges]
            } else {
                vec![
                    FounderSupportingMaterialRole::RiskRationale,
                    FounderSupportingMaterialRole::CompensatingControl,
                ]
            };
            let materials = FounderSupportingMaterialCollection::from_confirmed(
                roles
                    .iter()
                    .enumerate()
                    .map(|(index, role)| {
                        confirmed_founder_supporting_material(
                            &review,
                            &kernel,
                            &format!("material:submit:{index}"),
                            *role,
                            coverage.clone(),
                        )
                    })
                    .collect(),
            )
            .expect("confirmed material collection");
            let command = build_guided_founder_verdict_with_materials(
                &review,
                guided_verdict_input(selection),
                kernel.session().expect("session"),
                &materials,
            )
            .expect("build complete command");
            for omit_materials in [false, true] {
                let task_view = review.task_view.clone();
                let graph = review.evidence_graph.clone().expect("bound graph");
                let sends = Cell::new(0);
                let result = block_on_ready(submit_guided_founder_verdict_materials_via(
                    &kernel,
                    GuidedFounderVerdictSubmission {
                        command: command.clone(),
                        selection,
                        materials: if omit_materials {
                            None
                        } else {
                            Some(&materials)
                        },
                        recovery_path: None,
                    },
                    now,
                    move |_| {
                        std::future::ready(Ok(GetTaskViewResponse {
                            outcome: Some(get_task_view_response::Outcome::View(task_view)),
                        }))
                    },
                    move |_| {
                        std::future::ready(Ok(GetEvidenceGraphResponse {
                            outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                        }))
                    },
                    |request| {
                        sends.set(sends.get() + 1);
                        assert_eq!(request.command.as_ref(), Some(&command));
                        std::future::ready(Ok(guided_verdict_response(&command, false)))
                    },
                ));
                if omit_materials {
                    assert!(
                        result.is_err(),
                        "a sealed command alone must not bypass confirmed material preflight"
                    );
                    assert_eq!(sends.get(), 0);
                } else {
                    assert!(matches!(
                        result,
                        Ok(GuidedFounderVerdictAttempt::Committed(_))
                    ));
                    assert_eq!(sends.get(), 1);
                }
            }
        }
    }

    #[test]
    fn guided_founder_verdict_durable_record_precedes_send_and_replays_with_new_session() {
        let root = tempfile::tempdir().expect("isolated recovery directory");
        let path = root.path().join("pending.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "old-session-must-not-be-persisted",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject);
        let task_view = review.task_view;
        let graph = review.evidence_graph.expect("graph");
        let attempt = block_on_ready(submit_guided_founder_verdict_materials_via(
            &kernel,
            GuidedFounderVerdictSubmission {
                command: command.clone(),
                selection: GuidedFounderVerdictSelection::Reject,
                materials: None,
                recovery_path: Some(&path),
            },
            now,
            move |_| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            move |_| {
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                }))
            },
            |request| {
                let persisted = std::fs::read_to_string(&path).expect("record durable BEFORE send");
                assert!(!persisted.contains("old-session-must-not-be-persisted"));
                assert!(!persisted.contains("session_id"));
                assert!(!persisted.contains("granted_permission"));
                assert_eq!(request.command.as_ref(), Some(&command));
                std::future::ready(Err("connection lost after Authority commit".into()))
            },
        ))
        .expect("unknown result");
        assert!(matches!(
            attempt,
            GuidedFounderVerdictAttempt::OutcomeUnknown(_)
        ));
        let before = std::fs::read(&path).expect("saved bytes");
        drop(kernel);
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(3600);
        let new_kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "new-session",
            &["local.founder-verdict.issue"],
            ClientSurface::Tui,
            later,
        );
        let recovered =
            DurableFounderVerdictRecovery::read(&path).expect("new process reads record");
        assert_eq!(
            recovered.command_id(),
            guided_founder_verdict_issue(&command)
                .expect("issue")
                .metadata
                .as_ref()
                .expect("metadata")
                .command_id
        );
        let replay = block_on_ready(founder_recovery::retry_durable_founder_verdict_via(
            &new_kernel,
            &recovered,
            later,
            |request| {
                assert_eq!(
                    request.client.as_ref().expect("new metadata").session_id,
                    "new-session"
                );
                assert_eq!(request.command.as_ref(), Some(&command));
                std::future::ready(Ok(guided_verdict_response(&command, true)))
            },
        ))
        .expect("same principal may reconcile without an old Task action or live old proof");
        assert!(
            matches!(replay, DurableFounderVerdictAttempt::Committed(result) if result.replayed())
        );
        assert_eq!(std::fs::read(path).expect("record retained"), before);
    }

    #[test]
    fn guided_apply_accepts_owner_evidence_refs_but_requires_exact_verdict_id() {
        let issue = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Accept);
        let verdict_result = GuidedFounderVerdictResult {
            authority: guided_verdict_response(&issue, false)
                .authority_result
                .expect("issued Founder Verdict"),
            await_token: None,
            projection_warning: None,
        };
        let apply = build_guided_founder_apply_command(&issue, &verdict_result)
            .expect("build exact Founder Verdict Apply");
        let mut result = guided_apply_response(&issue, &apply, false)
            .authority_result
            .expect("production-shaped Task Apply result");
        let verdict_id = verdict_result
            .authority
            .verdict
            .as_ref()
            .expect("Founder Verdict")
            .founder_verdict_id
            .clone();

        assert_eq!(
            result
                .committed_event
                .as_ref()
                .expect("VerdictApplied event")
                .evidence_refs,
            [
                verdict_id.clone(),
                format!("founder-verdict:{verdict_id}@issued"),
                format!("founder-verdict-state:{verdict_id}@1"),
            ]
        );
        assert!(guided_founder_apply_result_matches(
            &result,
            &apply,
            &verdict_result,
            "founder:guided-verdict",
        ));

        result
            .committed_event
            .as_mut()
            .expect("VerdictApplied event")
            .evidence_refs
            .retain(|reference| reference != &verdict_id);
        assert!(!guided_founder_apply_result_matches(
            &result,
            &apply,
            &verdict_result,
            "founder:guided-verdict",
        ));

        result
            .committed_event
            .as_mut()
            .expect("VerdictApplied event")
            .evidence_refs
            .push("founder-verdict:wrong".to_owned());
        assert!(!guided_founder_apply_result_matches(
            &result,
            &apply,
            &verdict_result,
            "founder:guided-verdict",
        ));
    }

    #[test]
    fn guided_founder_decision_persists_before_reads_then_issues_and_applies() {
        let root = tempfile::tempdir().expect("isolated recovery directory");
        let path = root.path().join("decision.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-decision",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
                "local.founder-verdict.apply",
            ],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let graph = review.evidence_graph.expect("evidence graph");
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject);
        let issued = command.clone();
        let applied = RefCell::new(None);
        let attempt = block_on_ready(Box::pin(
            founder_recovery::submit_durable_guided_founder_decision_via(
                &kernel,
                GuidedFounderVerdictSubmission {
                    command: command.clone(),
                    selection: GuidedFounderVerdictSelection::Reject,
                    materials: None,
                    recovery_path: None,
                },
                &path,
                now,
                |_| {
                    assert!(path.exists(), "capsule must precede the first read RPC");
                    std::future::ready(Ok(GetTaskViewResponse {
                        outcome: Some(get_task_view_response::Outcome::View(task_view)),
                    }))
                },
                |_| {
                    assert!(path.exists(), "capsule must precede evidence read");
                    std::future::ready(Ok(GetEvidenceGraphResponse {
                        outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                    }))
                },
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&issued));
                    std::future::ready(Ok(guided_verdict_response(&issued, false)))
                },
                |request| {
                    assert!(
                        founder_recovery::verdict_apply_recovery_path(&path).exists(),
                        "exact Apply capsule must precede the Task write"
                    );
                    let apply = request.command.expect("explicit Task Apply command");
                    applied.replace(Some(apply.clone()));
                    std::future::ready(Ok(guided_apply_response(&command, &apply, false)))
                },
            ),
        ))
        .expect("guided decision");
        let DurableFounderDecisionAttempt::Applied(result) = attempt else {
            panic!("Issue and Apply must both be known committed");
        };
        assert_eq!(result.task().status, DomainTaskStatus::Rejected as i32);
        assert_eq!(
            result.task().founder_verdict_id.as_deref(),
            Some(result.verdict().founder_verdict_id())
        );
        let saved = DurableFounderVerdictRecovery::read(&path).expect("durable Issue capsule");
        assert_eq!(
            saved.command_id(),
            guided_founder_verdict_issue(&command)
                .expect("Issue")
                .metadata
                .as_ref()
                .expect("metadata")
                .command_id
        );
        assert!(matches!(
            applied
                .borrow()
                .as_ref()
                .and_then(|command| command.command.as_ref()),
            Some(task_command::Command::ApplyFounderVerdict(_))
        ));
    }

    #[test]
    fn guided_founder_decision_recovery_replays_same_issue_and_same_apply() {
        let root = tempfile::tempdir().expect("isolated recovery directory");
        let path = root.path().join("decision.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:first",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
                "local.founder-verdict.apply",
            ],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let graph = review.evidence_graph.expect("evidence graph");
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Accept);
        let first_apply = RefCell::new(None);
        let attempt = block_on_ready(Box::pin(
            founder_recovery::submit_durable_guided_founder_decision_via(
                &kernel,
                GuidedFounderVerdictSubmission {
                    command: command.clone(),
                    selection: GuidedFounderVerdictSelection::Accept,
                    materials: None,
                    recovery_path: None,
                },
                &path,
                now,
                |_| {
                    std::future::ready(Ok(GetTaskViewResponse {
                        outcome: Some(get_task_view_response::Outcome::View(task_view)),
                    }))
                },
                |_| {
                    std::future::ready(Ok(GetEvidenceGraphResponse {
                        outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                    }))
                },
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&command));
                    std::future::ready(Ok(guided_verdict_response(&command, false)))
                },
                |request| {
                    assert!(
                        founder_recovery::verdict_apply_recovery_path(&path).exists(),
                        "exact Apply capsule must precede the Task write"
                    );
                    first_apply.replace(request.command);
                    std::future::ready(Err("Task response lost after commit".to_owned()))
                },
            ),
        ))
        .expect("unknown Apply remains recoverable");
        assert!(matches!(
            attempt,
            DurableFounderDecisionAttempt::Unknown {
                stage: GuidedFounderDecisionStage::Apply,
                ..
            }
        ));
        let original_bytes = std::fs::read(&path).expect("original recovery bytes");
        let saved = DurableFounderVerdictRecovery::read(&path).expect("saved recovery");
        let recovered_kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:recovered",
            &["local.founder-verdict.issue", "local.founder-verdict.apply"],
            ClientSurface::Tui,
            now,
        );
        let expected_apply = first_apply.into_inner().expect("first Apply command");
        let replay = block_on_ready(Box::pin(
            founder_recovery::retry_durable_founder_decision_via(
                &recovered_kernel,
                &saved,
                now,
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&command));
                    std::future::ready(Ok(guided_verdict_response(&command, true)))
                },
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&expected_apply));
                    std::future::ready(Ok(guided_apply_response(&command, &expected_apply, true)))
                },
            ),
        ))
        .expect("exact decision recovery");
        assert!(matches!(
            replay,
            DurableFounderDecisionAttempt::Applied(result)
                if result.verdict().replayed() && result.task_replayed()
        ));
        assert_eq!(
            std::fs::read(path).expect("recovery retained"),
            original_bytes
        );
    }

    #[test]
    fn guided_founder_decision_issue_unknown_does_not_apply_until_explicit_recovery() {
        let root = tempfile::tempdir().expect("isolated recovery directory");
        let path = root.path().join("decision.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:first",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
                "local.founder-verdict.apply",
            ],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let graph = review.evidence_graph.expect("evidence graph");
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject);
        let apply_sends = Cell::new(0_u64);
        let attempt = block_on_ready(Box::pin(
            founder_recovery::submit_durable_guided_founder_decision_via(
                &kernel,
                GuidedFounderVerdictSubmission {
                    command: command.clone(),
                    selection: GuidedFounderVerdictSelection::Reject,
                    materials: None,
                    recovery_path: None,
                },
                &path,
                now,
                |_| {
                    std::future::ready(Ok(GetTaskViewResponse {
                        outcome: Some(get_task_view_response::Outcome::View(task_view)),
                    }))
                },
                |_| {
                    std::future::ready(Ok(GetEvidenceGraphResponse {
                        outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                    }))
                },
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&command));
                    std::future::ready(Err("Issue response lost".to_owned()))
                },
                |_| {
                    apply_sends.set(apply_sends.get() + 1);
                    std::future::ready(Err("must not apply while Issue is unknown".to_owned()))
                },
            ),
        ))
        .expect("Issue uncertainty is durable");
        assert!(matches!(
            attempt,
            DurableFounderDecisionAttempt::Unknown {
                stage: GuidedFounderDecisionStage::Issue,
                ..
            }
        ));
        assert_eq!(apply_sends.get(), 0);
        assert!(!founder_recovery::verdict_apply_recovery_path(&path).exists());

        let saved = DurableFounderVerdictRecovery::read(&path).expect("saved Issue capsule");
        let recovered_kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:recovered",
            &["local.founder-verdict.issue", "local.founder-verdict.apply"],
            ClientSurface::Tui,
            now,
        );
        let recovered = block_on_ready(Box::pin(
            founder_recovery::retry_durable_founder_decision_via(
                &recovered_kernel,
                &saved,
                now,
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&command));
                    std::future::ready(Ok(guided_verdict_response(&command, true)))
                },
                |request| {
                    assert!(founder_recovery::verdict_apply_recovery_path(&path).exists());
                    let apply = request.command.expect("recovered Apply");
                    std::future::ready(Ok(guided_apply_response(&command, &apply, false)))
                },
            ),
        ))
        .expect("explicit recovery finishes the same decision");
        assert!(matches!(
            recovered,
            DurableFounderDecisionAttempt::Applied(_)
        ));
    }

    #[test]
    fn guided_founder_decision_recovery_keeps_apply_unknown_after_rejection() {
        let root = tempfile::tempdir().expect("isolated recovery directory");
        let path = root.path().join("decision.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:recovered",
            &["local.founder-verdict.issue", "local.founder-verdict.apply"],
            ClientSurface::Cli,
            now,
        );
        let original = RecoverableGuidedFounderVerdict {
            authenticated_principal_id: "founder:guided-verdict".to_owned(),
            session_id: "session:recovered".to_owned(),
            selection: GuidedFounderVerdictSelection::Reject,
            command: sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject),
        };
        DurableFounderVerdictRecovery::capture(&kernel, &original)
            .expect("capture")
            .write_new(&path)
            .expect("write recovery");
        let saved = DurableFounderVerdictRecovery::read(&path).expect("read recovery");
        let attempt = block_on_ready(Box::pin(
            founder_recovery::retry_durable_founder_decision_via(
                &kernel,
                &saved,
                now,
                |request| {
                    std::future::ready(Ok(guided_verdict_response(
                        request.command.as_ref().expect("same Issue"),
                        true,
                    )))
                },
                |_| {
                    std::future::ready(Ok(ExecuteTaskCommandResponse {
                        authority_result: Some(TaskCommandResult {
                            outcome: Some(task_command_result::Outcome::Error(
                                egopulse_domain_contracts::v01::egopulse::task::v1::TaskError {
                                    code: TaskErrorCode::PermissionDenied as i32,
                                    safe_detail_code: "CURRENT_PERMISSION_DENIED".to_owned(),
                                    ..Default::default()
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                },
            ),
        ))
        .expect("previously uncertain Apply cannot become a proven rejection");
        assert!(matches!(
            attempt,
            DurableFounderDecisionAttempt::Unknown {
                stage: GuidedFounderDecisionStage::Apply,
                ..
            }
        ));
    }

    #[test]
    fn guided_founder_verdict_durable_recovery_retains_unknown_on_rejection_and_denies_wrong_principal()
     {
        let root = tempfile::tempdir().expect("isolated recovery directory");
        let path = root.path().join("pending.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "original",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let recovery = RecoverableGuidedFounderVerdict {
            authenticated_principal_id: "founder:guided-verdict".into(),
            session_id: "original".into(),
            selection: GuidedFounderVerdictSelection::Reject,
            command: sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject),
        };
        DurableFounderVerdictRecovery::capture(&kernel, &recovery)
            .expect("capture")
            .write_new(&path)
            .expect("write ahead");
        let saved = DurableFounderVerdictRecovery::read(&path).expect("saved record");
        let bytes = std::fs::read(&path).expect("original bytes");
        for (principal, permissions, expect_send) in [
            ("other-founder", vec!["local.founder-verdict.issue"], false),
            ("founder:guided-verdict", vec!["local.task.read"], false),
            (
                "founder:guided-verdict",
                vec!["local.founder-verdict.issue"],
                true,
            ),
        ] {
            let fresh = authenticated_kernel_with_permissions(
                principal,
                "fresh",
                &permissions,
                ClientSurface::Cli,
                now,
            );
            let sends = Cell::new(0);
            let result = block_on_ready(founder_recovery::retry_durable_founder_verdict_via(
                &fresh,
                &saved,
                now,
                |request| {
                    sends.set(sends.get() + 1);
                    assert_eq!(request.command, Some(recovery.command.clone()));
                    std::future::ready(Ok(ExecuteFounderVerdictResponse {
                        authority_result: Some(VerdictCommandResult {
                            error_code: VerdictErrorCode::PermissionDenied as i32,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                },
            ));
            if principal == "other-founder" {
                assert!(matches!(
                    result,
                    Err(DurableFounderRecoveryError::PrincipalMismatch)
                ));
            } else {
                assert!(matches!(
                    result,
                    Ok(DurableFounderVerdictAttempt::Unknown { .. })
                ));
            }
            assert_eq!(sends.get(), usize::from(expect_send));
            assert_eq!(std::fs::read(&path).expect("retained record"), bytes);
        }
        let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).expect("record JSON");
        corrupt["sealed_command_hex"] = serde_json::json!("00");
        std::fs::write(&path, serde_json::to_vec(&corrupt).expect("corrupt JSON"))
            .expect("write corrupt fixture");
        assert!(matches!(
            DurableFounderVerdictRecovery::read(path),
            Err(DurableFounderRecoveryError::InvalidRecord)
        ));
    }

    #[test]
    fn guided_founder_verdict_and_material_durable_recovery_reject_another_store_before_send() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let original = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "original",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let new_store = authenticated_kernel_with_permissions_and_epoch(
            "founder:guided-verdict",
            "fresh",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
            "epoch:different-store",
        );
        let root = tempfile::tempdir().expect("isolated recovery");
        let verdict_path = root.path().join("verdict.json");
        let material_path = root.path().join("material.json");
        let recovery = RecoverableGuidedFounderVerdict {
            authenticated_principal_id: "founder:guided-verdict".into(),
            session_id: "original".into(),
            selection: GuidedFounderVerdictSelection::Reject,
            command: sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject),
        };
        DurableFounderVerdictRecovery::capture(&original, &recovery)
            .expect("capture")
            .write_new(&verdict_path)
            .expect("save");
        let prepared = prepared_founder_supporting_material(&original);
        DurableFounderMaterialRecovery::capture(&original, &prepared)
            .expect("capture")
            .write_new(&material_path)
            .expect("save");
        let saved_verdict =
            DurableFounderVerdictRecovery::read(&verdict_path).expect("read protected record");
        let saved_material =
            DurableFounderMaterialRecovery::read(&material_path).expect("read protected record");
        let verdict_result = block_on_ready(founder_recovery::retry_durable_founder_verdict_via(
            &new_store,
            &saved_verdict,
            now,
            |_| async { panic!("different store must not send") },
        ));
        let material_result = block_on_ready(founder_recovery::retry_durable_founder_material_via(
            &new_store,
            &saved_material,
            now,
            |_| async { panic!("different store must not send") },
        ));
        assert!(matches!(
            verdict_result,
            Err(DurableFounderRecoveryError::StoreMismatch)
        ));
        assert!(matches!(
            material_result,
            Err(DurableFounderRecoveryError::StoreMismatch)
        ));
    }

    #[test]
    fn guided_founder_verdict_builds_rework_from_confirmed_required_changes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_review_with_open_items(VerificationConclusion::Partial);
        let coverage = FounderSupportingMaterialCoverage {
            risk_category: RiskCategory::Unspecified as i32,
            discrepancy_ids: vec!["discrepancy:review:1".to_owned()],
            unverified_item_ids: vec!["unverified:review:1".to_owned()],
        };
        let required_changes = confirmed_founder_supporting_material(
            &review,
            &kernel,
            "material:required-changes:1",
            FounderSupportingMaterialRole::ReworkRequiredChanges,
            coverage.clone(),
        );
        let required_changes_artifact_id = required_changes.receipt().artifact_id.clone();
        let materials = FounderSupportingMaterialCollection::from_confirmed(vec![required_changes])
            .expect("unique confirmed material");

        let command = build_guided_founder_verdict_with_materials(
            &review,
            guided_verdict_input(GuidedFounderVerdictSelection::Rework),
            kernel.session().expect("authenticated test session"),
            &materials,
        )
        .expect("confirmed required changes build Rework");
        let issue = guided_founder_verdict_issue(&command).expect("Rework issue command");
        let directive = issue.rework_directive.as_ref().expect("Rework directive");
        assert_eq!(issue.decision, FounderVerdictDecision::Rework as i32);
        assert_eq!(
            issue.required_confirmation_class,
            ConfirmationClass::Explicit as i32
        );
        assert!(issue.risk_acceptances.is_empty());
        assert_eq!(
            directive.required_changes_artifact_id,
            required_changes_artifact_id
        );
        assert_eq!(directive.target_discrepancy_ids, coverage.discrepancy_ids);
        assert_eq!(
            directive.target_unverified_item_ids,
            coverage.unverified_item_ids
        );
        assert!(!directive.directive_id.trim().is_empty());
    }

    #[test]
    fn guided_founder_verdict_nonpassed_accept_requires_complete_confirmed_risk_materials() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_review_with_open_items(VerificationConclusion::Partial);
        let coverage = FounderSupportingMaterialCoverage {
            risk_category: RiskCategory::QualityResidual as i32,
            discrepancy_ids: vec!["discrepancy:review:1".to_owned()],
            unverified_item_ids: vec!["unverified:review:1".to_owned()],
        };
        let rationale = confirmed_founder_supporting_material(
            &review,
            &kernel,
            "material:risk-rationale:complete",
            FounderSupportingMaterialRole::RiskRationale,
            coverage.clone(),
        );
        let control = confirmed_founder_supporting_material(
            &review,
            &kernel,
            "material:compensating-control:complete",
            FounderSupportingMaterialRole::CompensatingControl,
            coverage.clone(),
        );
        let expected_rationale = rationale.receipt().artifact_id.clone();
        let expected_control = control.receipt().artifact_id.clone();
        let missing_control =
            FounderSupportingMaterialCollection::from_confirmed(vec![rationale.clone()])
                .expect("single confirmed rationale");
        assert!(matches!(
            build_guided_founder_verdict_with_materials(
                &review,
                guided_verdict_input(GuidedFounderVerdictSelection::Accept),
                kernel.session().expect("authenticated test session"),
                &missing_control,
            ),
            Err(ClientGuidedFounderVerdictError::MissingMaterial(_))
        ));

        let complete =
            FounderSupportingMaterialCollection::from_confirmed(vec![rationale, control])
                .expect("complete confirmed risk materials");
        let command = build_guided_founder_verdict_with_materials(
            &review,
            guided_verdict_input(GuidedFounderVerdictSelection::Accept),
            kernel.session().expect("authenticated test session"),
            &complete,
        )
        .expect("non-Passed Accept with complete risk materials");
        let issue = guided_founder_verdict_issue(&command).expect("risk Accept command");
        assert_eq!(issue.decision, FounderVerdictDecision::Accept as i32);
        assert_eq!(
            issue.required_confirmation_class,
            ConfirmationClass::ElevatedRiskAcceptance as i32
        );
        assert_eq!(issue.risk_acceptances.len(), 1);
        let risk = &issue.risk_acceptances[0];
        assert_eq!(risk.rationale_artifact_id, expected_rationale);
        assert_eq!(risk.compensating_control_artifact_ids, [expected_control]);
        assert_eq!(risk.discrepancy_ids, coverage.discrepancy_ids);
        assert_eq!(risk.unverified_item_ids, coverage.unverified_item_ids);
        assert!(!risk.risk_acceptance_id.trim().is_empty());
    }

    #[test]
    fn guided_founder_verdict_rejects_cross_scope_and_fabricated_coverage_materials() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_review_with_open_items(VerificationConclusion::Partial);
        let coverage = FounderSupportingMaterialCoverage {
            risk_category: RiskCategory::Unspecified as i32,
            discrepancy_ids: vec!["discrepancy:review:1".to_owned()],
            unverified_item_ids: vec!["unverified:review:1".to_owned()],
        };
        let old_scope = confirmed_founder_supporting_material(
            &review,
            &kernel,
            "material:old-scope",
            FounderSupportingMaterialRole::ReworkRequiredChanges,
            coverage,
        );
        let old_scope = FounderSupportingMaterialCollection::from_confirmed(vec![old_scope])
            .expect("old-scope confirmed material");
        let mut advanced_review = review.clone();
        advanced_review
            .task_view
            .task
            .as_mut()
            .expect("review Task")
            .revision += 1;
        advanced_review
            .task_view
            .metadata
            .as_mut()
            .expect("review metadata")
            .source_revisions
            .iter_mut()
            .find(|source| source.domain == SourceDomain::Task as i32)
            .expect("Task source")
            .revision += 1;
        assert!(matches!(
            build_guided_founder_verdict_with_materials(
                &advanced_review,
                guided_verdict_input(GuidedFounderVerdictSelection::Rework),
                kernel.session().expect("authenticated test session"),
                &old_scope,
            ),
            Err(ClientGuidedFounderVerdictError::BindingChanged)
        ));

        let fabricated = confirmed_founder_supporting_material(
            &review,
            &kernel,
            "material:fabricated-coverage",
            FounderSupportingMaterialRole::ReworkRequiredChanges,
            FounderSupportingMaterialCoverage {
                risk_category: RiskCategory::Unspecified as i32,
                discrepancy_ids: vec!["discrepancy:not-in-verification".to_owned()],
                unverified_item_ids: Vec::new(),
            },
        );
        let fabricated = FounderSupportingMaterialCollection::from_confirmed(vec![fabricated])
            .expect("receipt remains structurally confirmed");
        assert!(matches!(
            build_guided_founder_verdict_with_materials(
                &review,
                guided_verdict_input(GuidedFounderVerdictSelection::Rework),
                kernel.session().expect("authenticated test session"),
                &fabricated,
            ),
            Err(ClientGuidedFounderVerdictError::BindingChanged)
        ));
    }

    #[test]
    fn founder_supporting_material_durable_recovery_preserves_payload_across_session_and_rejection()
    {
        let root = tempfile::tempdir().expect("isolated material recovery");
        let path = root.path().join("material.json");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "material-old-session",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let prepared = prepared_founder_supporting_material(&kernel);
        let original_command = prepared.command().clone();
        let confirmed_response = founder_supporting_material_response(&prepared, true);
        let expected_address = prepared.capsule().expected_payload_address.clone();
        let first = block_on_ready(founder_recovery::submit_durable_founder_material_via(
            &kernel,
            prepared,
            &path,
            now,
            |request| {
                assert!(
                    path.exists(),
                    "write-ahead record must exist before sending"
                );
                assert_eq!(request.command.as_ref(), Some(&original_command));
                let text = std::fs::read_to_string(&path).expect("saved record");
                assert!(!text.contains("material-old-session"));
                assert!(!text.contains("session_id"));
                std::future::ready(Err("response lost after Stage/Seal".into()))
            },
        ));
        assert!(matches!(
            first,
            Err(ClientFounderSupportingMaterialError::Unknown { .. })
        ));
        let original_record = std::fs::read(&path).expect("saved bytes");
        drop(kernel);
        let current = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "material-new-session",
            &["local.founder-verdict.issue"],
            ClientSurface::Tui,
            now,
        );
        let saved =
            DurableFounderMaterialRecovery::read(&path).expect("read original frozen material");
        for response in [
            CreateFounderSupportingMaterialResponse {
                gateway_error: Some(LocalApiError {
                    code: LocalApiErrorCode::PermissionDenied as i32,
                    ..Default::default()
                }),
                ..Default::default()
            },
            confirmed_response,
        ] {
            let should_confirm = response.authority_result.is_some();
            let result = block_on_ready(founder_recovery::retry_durable_founder_material_via(
                &current,
                &saved,
                now,
                |request| {
                    assert_eq!(request.command.as_ref(), Some(&original_command));
                    assert_eq!(
                        request
                            .client
                            .as_ref()
                            .expect("current metadata")
                            .session_id,
                        "material-new-session"
                    );
                    std::future::ready(Ok(response))
                },
            ))
            .expect("read-only recovery authorization");
            match result {
                DurableFounderMaterialAttempt::Confirmed(receipt) => {
                    assert!(should_confirm);
                    assert_eq!(
                        receipt.receipt().canonical_payload.as_ref(),
                        Some(&expected_address)
                    );
                }
                DurableFounderMaterialAttempt::Unknown { .. } => assert!(!should_confirm),
            }
            assert_eq!(
                std::fs::read(&path).expect("retained record"),
                original_record
            );
        }
        let other = authenticated_kernel_with_permissions(
            "other-founder",
            "other-session",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let denied = block_on_ready(founder_recovery::retry_durable_founder_material_via(
            &other,
            &saved,
            now,
            |_| async { panic!("a different principal must never send the saved material") },
        ));
        assert!(matches!(
            denied,
            Err(DurableFounderRecoveryError::PrincipalMismatch)
        ));
        let mut corrupt: serde_json::Value =
            serde_json::from_slice(&original_record).expect("record JSON");
        corrupt["canonical_payload_hex"] = serde_json::json!("00");
        std::fs::write(&path, serde_json::to_vec(&corrupt).expect("corrupt JSON"))
            .expect("corrupt fixture");
        assert!(matches!(
            DurableFounderMaterialRecovery::read(path),
            Err(DurableFounderRecoveryError::InvalidRecord)
        ));
    }

    #[test]
    fn founder_supporting_material_existing_durable_record_stops_a_new_send() {
        let root = tempfile::tempdir().expect("isolated material recovery");
        let path = root.path().join("material.json");
        std::fs::write(&path, b"retained previous record").expect("existing record");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "original",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let prepared = prepared_founder_supporting_material(&kernel);
        let sent = Cell::new(false);
        let result = block_on_ready(founder_recovery::submit_durable_founder_material_via(
            &kernel,
            prepared,
            &path,
            now,
            |_| {
                sent.set(true);
                std::future::ready(Err("must not send".into()))
            },
        ));
        assert!(matches!(
            result,
            Err(ClientFounderSupportingMaterialError::RecoveryStorage)
        ));
        assert!(!sent.get());
        assert_eq!(
            std::fs::read(path).expect("unchanged record"),
            b"retained previous record"
        );
    }

    #[test]
    fn founder_supporting_material_builder_submits_exact_trusted_capsule() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let prepared = prepared_founder_supporting_material(&kernel);
        let expected_command = prepared.command().clone();
        let expected_capsule = prepared.capsule().clone();
        let response = founder_supporting_material_response(&prepared, false);
        let sent = RefCell::new(None);
        let confirmed = block_on_ready(submit_founder_supporting_material_via(
            &kernel,
            prepared,
            now,
            |request| {
                sent.replace(Some(request.clone()));
                std::future::ready(Ok(response))
            },
        ))
        .expect("supporting material committed");

        let sent = sent.into_inner().expect("request sent");
        assert!(sent.client.is_some());
        assert_eq!(sent.command.as_ref(), Some(&expected_command));
        assert_eq!(
            confirmed.receipt().canonical_payload.as_ref(),
            Some(&expected_capsule.expected_payload_address)
        );
        assert_eq!(
            confirmed.receipt().correlation_id,
            expected_command
                .metadata
                .as_ref()
                .expect("command metadata")
                .correlation_id
        );
    }

    #[test]
    fn founder_supporting_material_rejects_tampered_receipt_as_unknown() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let prepared = prepared_founder_supporting_material(&kernel);
        let expected_capsule = prepared.capsule().clone();
        let mut response = founder_supporting_material_response(&prepared, false);
        response
            .authority_result
            .as_mut()
            .expect("material receipt")
            .canonical_payload = Some(review_address('f'));

        let result = block_on_ready(submit_founder_supporting_material_via(
            &kernel,
            prepared,
            now,
            move |_request| std::future::ready(Ok(response)),
        ));
        let Err(ClientFounderSupportingMaterialError::Unknown { recovery }) = result else {
            panic!("tampered receipt must not confirm the write");
        };
        assert_eq!(recovery.prepared().capsule(), &expected_capsule);
        assert!(recovery.request().client.is_some());
    }

    #[test]
    fn founder_supporting_material_retry_rejection_retains_exact_unknown_capsule() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.founder-verdict.issue"],
            ClientSurface::Cli,
            now,
        );
        let prepared = prepared_founder_supporting_material(&kernel);
        let expected_capsule = prepared.capsule().clone();
        let first_sent = RefCell::new(None);
        let result = block_on_ready(submit_founder_supporting_material_via(
            &kernel,
            prepared,
            now,
            |request| {
                first_sent.replace(Some(request));
                std::future::ready(Err("response lost after write".to_owned()))
            },
        ));
        let Err(ClientFounderSupportingMaterialError::Unknown { recovery }) = result else {
            panic!("lost response must retain supporting-material recovery");
        };
        let frozen_request = recovery.request().clone();
        let retry_sent = RefCell::new(None);
        let rejected = CreateFounderSupportingMaterialResponse {
            authority_result: None,
            await_token: None,
            gateway_error: Some(LocalApiError {
                code: LocalApiErrorCode::PermissionDenied as i32,
                safe_fingerprint: "founder-material/permission-denied/v1".to_owned(),
                retryable: false,
                required_action_code: None,
                current_position: None,
                correlation_id: "correlation:founder-material:1".to_owned(),
            }),
        };
        let retried = block_on_ready(retry_founder_supporting_material_via(
            &kernel,
            &recovery,
            |request| {
                retry_sent.replace(Some(request));
                std::future::ready(Ok(rejected))
            },
        ));
        let Err(ClientFounderSupportingMaterialError::Unknown { recovery: retained }) = retried
        else {
            panic!("retry rejection cannot resolve the earlier unknown write");
        };

        assert_eq!(first_sent.into_inner(), Some(frozen_request.clone()));
        assert_eq!(retry_sent.into_inner(), Some(frozen_request.clone()));
        assert_eq!(retained.request(), &frozen_request);
        assert_eq!(retained.prepared().capsule(), &expected_capsule);
        assert_eq!(retained.prepared().session_id(), "session:guided-verdict");
    }

    #[test]
    fn guided_founder_verdict_builds_passed_accept_from_current_review() {
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let input = guided_verdict_input(GuidedFounderVerdictSelection::Accept);
        let expected_metadata = input.metadata.clone();
        let command = build_guided_founder_verdict(&review, input).expect("Passed Accept");
        let issue = match command.command.as_ref().unwrap() {
            verdict_command::Command::IssueFounderVerdict(issue) => issue,
            _ => panic!("guided verdict must issue a Founder Verdict"),
        };
        let scope = issue.scope.as_ref().unwrap();
        assert_eq!(scope.task_id, "task:review");
        assert_eq!(scope.task_revision, 7);
        assert_eq!(scope.work_revision, 2);
        assert_eq!(scope.artifact_set_id, "artifact-set:review");
        assert_eq!(scope.verification_artifact_id, "verification:review");
        assert_eq!(
            scope.acceptance_contract_ref,
            review
                .task_view
                .task
                .as_ref()
                .unwrap()
                .acceptance_contract_ref
        );
        assert_eq!(issue.decision, FounderVerdictDecision::Accept as i32);
        assert_eq!(
            issue.observed_verification_conclusion,
            VerificationConclusion::Passed as i32
        );
        assert_eq!(
            issue.required_confirmation_class,
            ConfirmationClass::Explicit as i32
        );
        assert!(issue.risk_acceptances.is_empty());
        assert!(issue.rework_directive.is_none());
        assert!(issue.rationale_artifact_id.is_none());
        assert!(issue.supersedes_founder_verdict_id.is_none());
        let metadata = issue.metadata.as_ref().unwrap();
        assert_eq!(metadata.command_id, expected_metadata.command_id);
        assert_eq!(metadata.idempotency_key, expected_metadata.idempotency_key);
        assert_eq!(
            metadata.idempotency_scope,
            expected_metadata.idempotency_scope
        );
        assert_eq!(metadata.issued_at, expected_metadata.issued_at);
        assert_eq!(metadata.correlation_id, expected_metadata.correlation_id);
        assert_eq!(metadata.causation_id, expected_metadata.causation_id);
        assert!(guided_verdict_digest_is_complete(
            &metadata.request_digest_sha256
        ));

        let replay = build_guided_founder_verdict(
            &review,
            GuidedFounderVerdictInput {
                metadata: metadata.clone(),
                ..guided_verdict_input(GuidedFounderVerdictSelection::Accept)
            },
        )
        .expect("same metadata and review rebuild the replay payload");
        assert_eq!(replay, command);
    }

    #[test]
    fn guided_founder_verdict_builds_reject_without_supporting_artifact_placeholders() {
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let command = build_guided_founder_verdict(
            &review,
            guided_verdict_input(GuidedFounderVerdictSelection::Reject),
        )
        .expect("Reject with an explicit reason");
        let issue = match command.command.as_ref().unwrap() {
            verdict_command::Command::IssueFounderVerdict(issue) => issue,
            _ => panic!("guided verdict must issue a Founder Verdict"),
        };
        assert_eq!(issue.decision, FounderVerdictDecision::Reject as i32);
        assert_eq!(issue.reason_code, "founder-reviewed-result");
        assert!(issue.risk_acceptances.is_empty());
        assert!(issue.rework_directive.is_none());
        assert!(issue.rationale_artifact_id.is_none());

        let mut missing_reason = guided_verdict_input(GuidedFounderVerdictSelection::Reject);
        missing_reason.reason_code = "  ".to_owned();
        assert!(matches!(
            build_guided_founder_verdict(&review, missing_reason),
            Err(ClientGuidedFounderVerdictError::InvalidInput(
                "Reject requires a non-empty reason_code"
            ))
        ));
    }

    #[test]
    fn guided_founder_verdict_requires_real_material_for_override_and_rework() {
        let non_passed = verdict_pending_review(VerificationConclusion::Partial);
        assert!(matches!(
            build_guided_founder_verdict(
                &non_passed,
                guided_verdict_input(GuidedFounderVerdictSelection::Accept),
            ),
            Err(
                ClientGuidedFounderVerdictError::NonPassedAcceptRequiresRiskMaterials {
                    conclusion: VerificationConclusion::Partial,
                }
            )
        ));

        let passed = verdict_pending_review(VerificationConclusion::Passed);
        assert!(matches!(
            build_guided_founder_verdict(
                &passed,
                guided_verdict_input(GuidedFounderVerdictSelection::Rework),
            ),
            Err(ClientGuidedFounderVerdictError::ReworkRequiresDirectiveMaterials)
        ));
    }

    #[test]
    fn guided_founder_verdict_rejects_stale_or_non_actionable_review() {
        let mut mismatched = verdict_pending_review(VerificationConclusion::Passed);
        mismatched.evidence_graph.as_mut().unwrap().task_id = "task:other".to_owned();
        assert!(matches!(
            build_guided_founder_verdict(
                &mismatched,
                guided_verdict_input(GuidedFounderVerdictSelection::Accept),
            ),
            Err(ClientGuidedFounderVerdictError::Review(
                ClientTaskResultReviewError::Integrity {
                    stage: TaskResultReviewStage::Evidence,
                    detail: "evidence graph binding mismatch",
                }
            ))
        ));

        let mut non_actionable = verdict_pending_review(VerificationConclusion::Passed);
        non_actionable.task_view.available_actions.clear();
        assert!(matches!(
            build_guided_founder_verdict(
                &non_actionable,
                guided_verdict_input(GuidedFounderVerdictSelection::Accept),
            ),
            Err(ClientGuidedFounderVerdictError::NonActionable(
                "SubmitFounderVerdict is not available in the current projection"
            ))
        ));
    }

    #[test]
    fn guided_founder_verdict_submission_preflights_permissions_and_current_binding_before_send() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Accept);
        let denied = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &["local.task.read", "local.evidence.read"],
            ClientSurface::Cli,
            now,
        );
        let reads = Cell::new(0_u64);
        let sends = Cell::new(0_u64);
        let result = block_on_ready(submit_guided_founder_verdict_via(
            &denied,
            command.clone(),
            GuidedFounderVerdictSelection::Accept,
            now,
            |_request| {
                reads.set(reads.get() + 1);
                std::future::ready(Err("must-not-read-task".to_owned()))
            },
            |_request| {
                reads.set(reads.get() + 1);
                std::future::ready(Err("must-not-read-evidence".to_owned()))
            },
            |_request| {
                sends.set(sends.get() + 1);
                std::future::ready(Err("must-not-send".to_owned()))
            },
        ));
        assert!(matches!(
            result,
            Err(ClientGuidedFounderVerdictError::Kernel(
                KernelError::PermissionDenied(_)
            ))
        ));
        assert_eq!(reads.get(), 0);
        assert_eq!(sends.get(), 0);

        let allowed = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            now,
        );
        let mut wrong_scope = command;
        let issue = match wrong_scope.command.as_mut().unwrap() {
            verdict_command::Command::IssueFounderVerdict(issue) => issue,
            _ => unreachable!("guided command branch"),
        };
        issue.scope.as_mut().unwrap().task_revision += 1;
        set_verdict_digest(&mut wrong_scope);
        let sends = Cell::new(0_u64);
        let task_view = review.task_view.clone();
        let evidence_graph = review.evidence_graph.clone().unwrap();
        let result = block_on_ready(submit_guided_founder_verdict_via(
            &allowed,
            wrong_scope,
            GuidedFounderVerdictSelection::Accept,
            now,
            move |_request| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            move |_request| {
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(evidence_graph)),
                }))
            },
            |_request| {
                sends.set(sends.get() + 1);
                std::future::ready(Err("must-not-send".to_owned()))
            },
        ));
        assert!(matches!(
            result,
            Err(ClientGuidedFounderVerdictError::RequestDigestMismatch)
                | Err(ClientGuidedFounderVerdictError::BindingChanged)
        ));
        assert_eq!(sends.get(), 0);
    }

    #[test]
    fn guided_founder_verdict_submission_reports_authority_commit_without_inventing_projection_await()
     {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let evidence_graph = review.evidence_graph.clone().unwrap();
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Accept);
        let sent = RefCell::new(None);
        let mut response = guided_verdict_response(&command, false);
        response.await_token = Some(ProjectionAwaitToken {
            token: "unbound-await-token".to_owned(),
            required_source_revision: Some(SourceRevision {
                domain: SourceDomain::Task as i32,
                aggregate_id: "task:other".to_owned(),
                revision: 1,
                last_event_id: "task-event:other:1".to_owned(),
            }),
            expires_at: Some(Timestamp {
                seconds: 400,
                nanos: 0,
            }),
        });
        let result = block_on_ready(submit_guided_founder_verdict_via(
            &kernel,
            command.clone(),
            GuidedFounderVerdictSelection::Accept,
            now,
            move |_request| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            move |_request| {
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(evidence_graph)),
                }))
            },
            |request| {
                sent.replace(request.command.clone());
                std::future::ready(Ok(response))
            },
        ))
        .expect("guided verdict submission");
        let GuidedFounderVerdictAttempt::Committed(result) = result else {
            panic!("Authority result must be known");
        };
        assert!(result.committed());
        assert!(!result.replayed());
        assert_eq!(result.decision(), FounderVerdictDecision::Accept);
        assert_eq!(result.founder_verdict_id(), "founder-verdict:guided:1");
        assert!(result.await_token().is_none());
        assert!(result.projection_warning().is_none());
        assert_eq!(sent.into_inner(), Some(command));
    }

    #[test]
    fn guided_founder_verdict_response_loss_retries_the_exact_sealed_command() {
        let first_now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let retry_now = first_now + Duration::from_secs(10);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            first_now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let evidence_graph = review.evidence_graph.clone().unwrap();
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Reject);
        let first_sent = RefCell::new(None);
        let attempt = block_on_ready(submit_guided_founder_verdict_via(
            &kernel,
            command.clone(),
            GuidedFounderVerdictSelection::Reject,
            first_now,
            move |_request| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            move |_request| {
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(evidence_graph)),
                }))
            },
            |request| {
                first_sent.replace(request.command);
                std::future::ready(Err("response-lost".to_owned()))
            },
        ))
        .expect("unknown outcome is recoverable");
        let GuidedFounderVerdictAttempt::OutcomeUnknown(recovery) = attempt else {
            panic!("lost response must retain recovery");
        };
        assert_eq!(recovery.sealed_command(), &command);

        let retry_sent = RefCell::new(None);
        let retried = block_on_ready(retry_guided_founder_verdict_via(
            &kernel,
            &recovery,
            retry_now,
            |request| {
                retry_sent.replace(request.command.clone());
                std::future::ready(Ok(guided_verdict_response(
                    request.command.as_ref().unwrap(),
                    true,
                )))
            },
        ))
        .expect("exact retry");
        let GuidedFounderVerdictAttempt::Committed(result) = retried else {
            panic!("replayed Authority result must be known");
        };
        assert!(result.replayed());
        assert_eq!(first_sent.into_inner(), Some(command.clone()));
        assert_eq!(retry_sent.into_inner(), Some(command.clone()));

        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let evidence_graph = review.evidence_graph.unwrap();
        let attempt = block_on_ready(submit_guided_founder_verdict_via(
            &kernel,
            command.clone(),
            GuidedFounderVerdictSelection::Reject,
            first_now,
            move |_request| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            move |_request| {
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(evidence_graph)),
                }))
            },
            move |_request| std::future::ready(Err("response-lost".to_owned())),
        ))
        .expect("lost response retains the exact command");
        let GuidedFounderVerdictAttempt::OutcomeUnknown(recovery) = attempt else {
            panic!("lost response must retain recovery before a permission rejection");
        };
        let retry_sent = RefCell::new(None);
        let retried = block_on_ready(retry_guided_founder_verdict_via(
            &kernel,
            &recovery,
            retry_now,
            |request| {
                retry_sent.replace(request.command);
                std::future::ready(Ok(ExecuteFounderVerdictResponse {
                    authority_result: Some(VerdictCommandResult {
                        error_code: VerdictErrorCode::PermissionDenied as i32,
                        safe_error_fingerprint: Some(
                            "verdict/retry-permission-denied/v1".to_owned(),
                        ),
                        ..Default::default()
                    }),
                    await_token: None,
                    gateway_error: None,
                }))
            },
        ))
        .expect("a retry rejection cannot resolve the earlier unknown outcome");
        let GuidedFounderVerdictAttempt::OutcomeUnknown(retained) = retried else {
            panic!("non-committed retry rejection must preserve unknown outcome");
        };
        assert_eq!(recovery.sealed_command(), &command);
        assert_eq!(retained.sealed_command(), &command);
        assert_eq!(retry_sent.into_inner(), Some(command));
    }

    #[test]
    fn guided_founder_verdict_wrong_scope_and_incomplete_responses_remain_outcome_unknown() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            now,
        );
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Accept);
        let mut wrong_scope = guided_verdict_response(&command, false);
        wrong_scope
            .authority_result
            .as_mut()
            .unwrap()
            .verdict
            .as_mut()
            .unwrap()
            .scope
            .as_mut()
            .unwrap()
            .task_id = "task:wrong".to_owned();
        let mut incomplete = guided_verdict_response(&command, false);
        incomplete.authority_result.as_mut().unwrap().state = None;
        let mut wrong_principal = guided_verdict_response(&command, false);
        wrong_principal
            .authority_result
            .as_mut()
            .unwrap()
            .verdict
            .as_mut()
            .unwrap()
            .authority_proof
            .as_mut()
            .unwrap()
            .authenticated_founder_principal_id = "founder:other".to_owned();

        for response in [
            wrong_scope,
            wrong_principal,
            incomplete,
            ExecuteFounderVerdictResponse::default(),
        ] {
            let review = verdict_pending_review(VerificationConclusion::Passed);
            let task_view = review.task_view.clone();
            let evidence_graph = review.evidence_graph.unwrap();
            let attempt = block_on_ready(submit_guided_founder_verdict_via(
                &kernel,
                command.clone(),
                GuidedFounderVerdictSelection::Accept,
                now,
                move |_request| {
                    std::future::ready(Ok(GetTaskViewResponse {
                        outcome: Some(get_task_view_response::Outcome::View(task_view)),
                    }))
                },
                move |_request| {
                    std::future::ready(Ok(GetEvidenceGraphResponse {
                        outcome: Some(get_evidence_graph_response::Outcome::Graph(evidence_graph)),
                    }))
                },
                move |_request| std::future::ready(Ok(response)),
            ))
            .expect("uncertain response remains recoverable");
            let GuidedFounderVerdictAttempt::OutcomeUnknown(recovery) = attempt else {
                panic!("mismatched response must not report success");
            };
            assert_eq!(recovery.sealed_command(), &command);
        }
    }

    #[test]
    fn guided_founder_verdict_authority_rejection_is_certain_and_not_retried_as_unknown() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-verdict",
            "session:guided-verdict",
            &[
                "local.task.read",
                "local.evidence.read",
                "local.founder-verdict.issue",
            ],
            ClientSurface::Cli,
            now,
        );
        let review = verdict_pending_review(VerificationConclusion::Passed);
        let task_view = review.task_view.clone();
        let evidence_graph = review.evidence_graph.unwrap();
        let command = sealed_guided_verdict_command(GuidedFounderVerdictSelection::Accept);
        let rejection = ExecuteFounderVerdictResponse {
            authority_result: Some(VerdictCommandResult {
                error_code: VerdictErrorCode::ScopeStale as i32,
                safe_error_fingerprint: Some("verdict/scope-stale/v1".to_owned()),
                ..Default::default()
            }),
            await_token: None,
            gateway_error: None,
        };
        let result = block_on_ready(submit_guided_founder_verdict_via(
            &kernel,
            command,
            GuidedFounderVerdictSelection::Accept,
            now,
            move |_request| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            move |_request| {
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(evidence_graph)),
                }))
            },
            move |_request| std::future::ready(Ok(rejection)),
        ));
        assert!(matches!(
            result,
            Err(ClientGuidedFounderVerdictError::Authority {
                error_code,
                safe_error_fingerprint: Some(fingerprint),
            }) if error_code == VerdictErrorCode::ScopeStale as i32
                && fingerprint == "verdict/scope-stale/v1"
        ));
    }

    #[test]
    fn task_result_review_reads_derived_evidence_with_older_graph_position() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let kernel = authenticated_kernel_with_permissions(
            "founder:review",
            "session:review",
            &["local.task.read", "local.evidence.read"],
            ClientSurface::Cli,
            now,
        );
        let (task_view, graph) = task_result_fixture();
        let captured_task = RefCell::new(None);
        let captured_evidence = RefCell::new(None);
        let result = block_on_ready(read_task_result_review_via(
            &kernel,
            "task:review",
            now,
            |request| {
                *captured_task.borrow_mut() = Some(request);
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view.clone())),
                }))
            },
            |request| {
                *captured_evidence.borrow_mut() = Some(request);
                std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(graph.clone())),
                }))
            },
        ))
        .expect("valid projected review");
        assert_eq!(result.task_view, task_view);
        assert_eq!(result.evidence_graph.as_ref(), Some(&graph));
        assert_eq!(
            result.task_view.task.as_ref().unwrap().status,
            TaskStatus::Active as i32,
            "read-only review must not derive completion"
        );
        assert_eq!(result.task_view.redactions.len(), 1);
        assert_eq!(result.evidence_graph.unwrap().redactions.len(), 1);
        let task_request = captured_task.borrow();
        assert_eq!(task_request.as_ref().unwrap().task_id, "task:review");
        let evidence_request = captured_evidence.borrow();
        let evidence_request = evidence_request.as_ref().unwrap();
        assert_eq!(evidence_request.task_id, "task:review");
        assert_eq!(evidence_request.artifact_set_id, "artifact-set:review");
        assert_eq!(
            evidence_request.minimum_position.as_ref().unwrap(),
            task_view
                .metadata
                .as_ref()
                .unwrap()
                .position
                .as_ref()
                .unwrap()
        );
        assert!(
            graph
                .metadata
                .as_ref()
                .unwrap()
                .position
                .as_ref()
                .unwrap()
                .sequence
                < task_view
                    .metadata
                    .as_ref()
                    .unwrap()
                    .position
                    .as_ref()
                    .unwrap()
                    .sequence
        );
    }

    #[test]
    fn task_result_review_distinguishes_verdict_issue_version_from_state_revision() {
        let (mut view, _) = task_result_fixture();
        view.founder_verdict_state.as_mut().unwrap().revision = 2;
        view.metadata
            .as_mut()
            .unwrap()
            .source_revisions
            .iter_mut()
            .find(|source| source.domain == SourceDomain::FounderVerdict as i32)
            .unwrap()
            .revision = 2;
        assert!(validate_task_result_view(&view, "task:review").is_ok());

        let mut stale_source = view.clone();
        stale_source
            .metadata
            .as_mut()
            .unwrap()
            .source_revisions
            .iter_mut()
            .find(|source| source.domain == SourceDomain::FounderVerdict as i32)
            .unwrap()
            .revision = 1;
        assert!(matches!(
            validate_task_result_view(&stale_source, "task:review"),
            Err(ClientTaskResultReviewError::Integrity {
                stage: TaskResultReviewStage::Task,
                detail: "Founder Verdict source revision mismatch",
            })
        ));

        let mut missing_issue_version = view;
        missing_issue_version
            .founder_verdict
            .as_mut()
            .unwrap()
            .version = 0;
        assert!(matches!(
            validate_task_result_view(&missing_issue_version, "task:review"),
            Err(ClientTaskResultReviewError::Integrity {
                stage: TaskResultReviewStage::Task,
                detail: "Founder Verdict binding mismatch",
            })
        ));
    }

    #[test]
    fn task_result_review_without_artifacts_stops_after_one_rpc() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let kernel =
            authenticated_kernel("founder:review", "session:review", "local.task.read", now);
        let (mut task_view, _) = task_result_fixture();
        let task = task_view.task.as_mut().unwrap();
        task.artifact_set_id = None;
        task.verification_artifact_id = None;
        task.founder_verdict_id = None;
        task_view.artifact_set = None;
        task_view.verification = None;
        task_view.founder_verdict = None;
        task_view.founder_verdict_state = None;
        task_view
            .metadata
            .as_mut()
            .unwrap()
            .source_revisions
            .retain(|source| source.domain == SourceDomain::Task as i32);
        let evidence_calls = Cell::new(0);
        let result = block_on_ready(read_task_result_review_via(
            &kernel,
            "task:review",
            now,
            |_| {
                std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                }))
            },
            |_| {
                evidence_calls.set(evidence_calls.get() + 1);
                std::future::ready(Err("must not dispatch".to_owned()))
            },
        ))
        .expect("Task without ArtifactSet");
        assert!(result.evidence_graph.is_none());
        assert_eq!(evidence_calls.get(), 0);
    }

    #[test]
    fn task_result_review_permissions_and_remote_failures_keep_stage_and_zero_dispatch() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let denied = authenticated_kernel(
            "founder:review",
            "session:review",
            "local.evidence.read",
            now,
        );
        let task_calls = Cell::new(0);
        let evidence_calls = Cell::new(0);
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &denied,
                "task:review",
                now,
                |_| {
                    task_calls.set(task_calls.get() + 1);
                    std::future::ready(Err("not called".to_owned()))
                },
                |_| {
                    evidence_calls.set(evidence_calls.get() + 1);
                    std::future::ready(Err("not called".to_owned()))
                },
            )),
            Err(ClientTaskResultReviewError::Kernel {
                stage: TaskResultReviewStage::Task,
                ..
            })
        ));
        assert_eq!((task_calls.get(), evidence_calls.get()), (0, 0));
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &denied,
                "  ",
                now,
                |_| std::future::ready(Err("not called".to_owned())),
                |_| std::future::ready(Err("not called".to_owned())),
            )),
            Err(ClientTaskResultReviewError::InvalidInput(_))
        ));

        let task_only =
            authenticated_kernel("founder:review", "session:review", "local.task.read", now);
        let (task_view, _) = task_result_fixture();
        let evidence_calls = Cell::new(0);
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &task_only,
                "task:review",
                now,
                |_| std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                })),
                |_| {
                    evidence_calls.set(evidence_calls.get() + 1);
                    std::future::ready(Err("not called".to_owned()))
                },
            )),
            Err(ClientTaskResultReviewError::Kernel {
                stage: TaskResultReviewStage::Evidence,
                ..
            })
        ));
        assert_eq!(evidence_calls.get(), 0);

        let both = authenticated_kernel_with_permissions(
            "founder:review",
            "session:review",
            &["local.task.read", "local.evidence.read"],
            ClientSurface::Cli,
            now,
        );
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &both,
                "task:review",
                now,
                |_| std::future::ready(Err("offline".to_owned())),
                |_| std::future::ready(Err("not called".to_owned())),
            )),
            Err(ClientTaskResultReviewError::Transport {
                stage: TaskResultReviewStage::Task,
                ..
            })
        ));
        let (task_view, _) = task_result_fixture();
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &both,
                "task:review",
                now,
                |_| std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                })),
                |_| std::future::ready(Ok(GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Error(LocalApiError {
                        code: LocalApiErrorCode::NotFound as i32,
                        ..Default::default()
                    })),
                })),
            )),
            Err(ClientTaskResultReviewError::Api {
                stage: TaskResultReviewStage::Evidence,
                ..
            })
        ));

        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &both,
                "task:review",
                now,
                |_| std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::Error(LocalApiError {
                        code: LocalApiErrorCode::NotFound as i32,
                        ..Default::default()
                    })),
                })),
                |_| std::future::ready(Err("not called".to_owned())),
            )),
            Err(ClientTaskResultReviewError::Api {
                stage: TaskResultReviewStage::Task,
                ..
            })
        ));

        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &both,
                "task:review",
                now,
                |_| std::future::ready(Ok(GetTaskViewResponse { outcome: None })),
                |_| std::future::ready(Err("not called".to_owned())),
            )),
            Err(ClientTaskResultReviewError::Integrity {
                stage: TaskResultReviewStage::Task,
                ..
            })
        ));

        let (task_view, _) = task_result_fixture();
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &both,
                "task:review",
                now,
                |_| std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                })),
                |_| std::future::ready(Err("offline".to_owned())),
            )),
            Err(ClientTaskResultReviewError::Transport {
                stage: TaskResultReviewStage::Evidence,
                ..
            })
        ));

        let (task_view, _) = task_result_fixture();
        assert!(matches!(
            block_on_ready(read_task_result_review_via(
                &both,
                "task:review",
                now,
                |_| std::future::ready(Ok(GetTaskViewResponse {
                    outcome: Some(get_task_view_response::Outcome::View(task_view)),
                })),
                |_| std::future::ready(Ok(GetEvidenceGraphResponse { outcome: None })),
            )),
            Err(ClientTaskResultReviewError::Integrity {
                stage: TaskResultReviewStage::Evidence,
                ..
            })
        ));
    }

    #[test]
    fn task_result_review_rejects_task_and_governance_binding_drift() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let kernel = authenticated_kernel_with_permissions(
            "founder:review",
            "session:review",
            &["local.task.read", "local.evidence.read"],
            ClientSurface::Cli,
            now,
        );
        let (baseline, graph) = task_result_fixture();
        let mut cases = Vec::new();
        let mut missing_metadata = baseline.clone();
        missing_metadata.metadata = None;
        cases.push(missing_metadata);
        let mut missing_task = baseline.clone();
        missing_task.task = None;
        cases.push(missing_task);
        let mut not_ready = baseline.clone();
        not_ready.metadata.as_mut().unwrap().health = ProjectionHealth::Rebuilding as i32;
        cases.push(not_ready);
        let mut stale = baseline.clone();
        stale.metadata.as_mut().unwrap().stale = true;
        cases.push(stale);
        let mut wrong_id = baseline.clone();
        wrong_id.task.as_mut().unwrap().task_id = "task:other".to_owned();
        cases.push(wrong_id);
        let mut artifact_set = baseline.clone();
        artifact_set.artifact_set.as_mut().unwrap().artifact_set_id =
            "artifact-set:other".to_owned();
        cases.push(artifact_set);
        let mut verification = baseline.clone();
        verification
            .verification
            .as_mut()
            .unwrap()
            .binding
            .as_mut()
            .unwrap()
            .lineage
            .as_mut()
            .unwrap()
            .task_id = "task:other".to_owned();
        cases.push(verification);
        let mut verdict = baseline.clone();
        verdict
            .founder_verdict
            .as_mut()
            .unwrap()
            .scope
            .as_mut()
            .unwrap()
            .artifact_set_id = "artifact-set:other".to_owned();
        cases.push(verdict);
        let mut state = baseline.clone();
        state
            .founder_verdict_state
            .as_mut()
            .unwrap()
            .founder_verdict_id = "verdict:other".to_owned();
        cases.push(state);
        let mut malformed_verdict = baseline.clone();
        malformed_verdict.founder_verdict.as_mut().unwrap().decision = i32::MAX;
        cases.push(malformed_verdict);

        for task_view in cases {
            let evidence_calls = Cell::new(0);
            assert!(matches!(
                block_on_ready(read_task_result_review_via(
                    &kernel,
                    "task:review",
                    now,
                    |_| std::future::ready(Ok(GetTaskViewResponse {
                        outcome: Some(get_task_view_response::Outcome::View(task_view)),
                    })),
                    |_| {
                        evidence_calls.set(evidence_calls.get() + 1);
                        std::future::ready(Ok(GetEvidenceGraphResponse {
                            outcome: Some(get_evidence_graph_response::Outcome::Graph(
                                graph.clone(),
                            )),
                        }))
                    },
                )),
                Err(ClientTaskResultReviewError::Integrity {
                    stage: TaskResultReviewStage::Task,
                    ..
                })
            ));
            assert_eq!(evidence_calls.get(), 0);
        }
    }

    #[test]
    fn task_result_review_rejects_graph_source_membership_duplicate_and_dangling_drift() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let kernel = authenticated_kernel_with_permissions(
            "founder:review",
            "session:review",
            &["local.task.read", "local.evidence.read"],
            ClientSurface::Cli,
            now,
        );
        let (task_view, baseline) = task_result_fixture();
        let mut cases = Vec::new();
        let mut wrong_task = baseline.clone();
        wrong_task.task_id = "task:other".to_owned();
        cases.push(wrong_task);
        let mut wrong_set = baseline.clone();
        wrong_set.artifact_set_id = "artifact-set:other".to_owned();
        cases.push(wrong_set);
        let mut wrong_epoch = baseline.clone();
        wrong_epoch
            .metadata
            .as_mut()
            .unwrap()
            .position
            .as_mut()
            .unwrap()
            .epoch = "epoch:other".to_owned();
        cases.push(wrong_epoch);
        let mut source = baseline.clone();
        source.metadata.as_mut().unwrap().source_revisions[0].revision += 1;
        cases.push(source);
        let mut duplicate = baseline.clone();
        duplicate.artifacts.push(duplicate.artifacts[0].clone());
        cases.push(duplicate);
        let mut duplicate_reference = baseline.clone();
        duplicate_reference.claims[0]
            .subject_artifact_ids
            .push("artifact:review".to_owned());
        cases.push(duplicate_reference);
        let mut extra_source = baseline.clone();
        extra_source
            .metadata
            .as_mut()
            .unwrap()
            .source_revisions
            .push(review_source(SourceDomain::Artifact, "artifact:extra", 1));
        cases.push(extra_source);
        let mut missing = baseline.clone();
        missing.evidence.clear();
        cases.push(missing);
        let mut dangling_claim = baseline.clone();
        dangling_claim.claims[0].subject_artifact_ids = vec!["artifact:missing".to_owned()];
        cases.push(dangling_claim);
        let mut dangling_evidence = baseline;
        dangling_evidence.evidence[0].claim_id = "claim:missing".to_owned();
        cases.push(dangling_evidence);

        for graph in cases {
            assert!(matches!(
                block_on_ready(read_task_result_review_via(
                    &kernel,
                    "task:review",
                    now,
                    |_| std::future::ready(Ok(GetTaskViewResponse {
                        outcome: Some(get_task_view_response::Outcome::View(task_view.clone())),
                    })),
                    |_| std::future::ready(Ok(GetEvidenceGraphResponse {
                        outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                    })),
                )),
                Err(ClientTaskResultReviewError::Integrity {
                    stage: TaskResultReviewStage::Evidence,
                    ..
                })
            ));
        }
    }
}
