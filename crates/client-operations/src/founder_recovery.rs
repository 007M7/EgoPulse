//! Client-owned write-ahead recovery. Authentication is always obtained from
//! the current local session; a saved record grants no permission.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::*;

const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictRecoveryRecordV1 {
    schema: String,
    authenticated_principal_id: String,
    projection_epoch: String,
    sealed_command_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictApplyRecoveryRecordV1 {
    schema: String,
    authenticated_principal_id: String,
    projection_epoch: String,
    sealed_issue_sha256: String,
    sealed_apply_hex: String,
}

/// Does not contain a session id, transport metadata, credential or cached grant.
#[derive(Clone)]
pub struct DurableFounderVerdictRecovery {
    record: VerdictRecoveryRecordV1,
    command: VerdictCommand,
    selection: GuidedFounderVerdictSelection,
    source_path: Option<PathBuf>,
    apply_command: Option<TaskCommand>,
}

#[derive(Debug, Error)]
pub enum DurableFounderRecoveryError {
    #[error("saved Founder recovery record is invalid or belongs to an unsupported format")]
    InvalidRecord,
    #[error("saved Founder recovery requires the original authenticated principal")]
    PrincipalMismatch,
    #[error("saved Founder recovery belongs to a different projection store epoch")]
    StoreMismatch,
    #[error(
        "Founder recovery could not be persisted or read; an existing record is never overwritten"
    )]
    Storage,
}

pub enum DurableFounderVerdictAttempt {
    Committed(Box<GuidedFounderVerdictResult>),
    /// The saved command remains unchanged. A current rejection cannot prove
    /// whether an earlier transport-unknown attempt committed.
    Unknown {
        safe_reason_code: &'static str,
    },
}

pub enum DurableFounderDecisionAttempt {
    Applied(Box<GuidedFounderDecisionResult>),
    /// The original authenticated Issue capsule remains the recovery root.
    /// Its exact replay deterministically reconstructs the same Apply command.
    Unknown {
        stage: GuidedFounderDecisionStage,
        safe_reason_code: &'static str,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialRecoveryRecordV1 {
    schema: String,
    authenticated_principal_id: String,
    projection_epoch: String,
    sealed_command_hex: String,
    canonical_payload_hex: String,
}

#[derive(Clone)]
pub struct DurableFounderMaterialRecovery {
    record: MaterialRecoveryRecordV1,
    command: CreateFounderSupportingMaterialCommand,
    payload: FounderSupportingMaterial,
}

pub enum DurableFounderMaterialAttempt {
    Confirmed(Box<ConfirmedFounderSupportingMaterialReceipt>),
    Unknown { safe_reason_code: &'static str },
}

impl DurableFounderMaterialRecovery {
    pub(super) fn capture(
        kernel: &ClientKernel,
        prepared: &PreparedFounderSupportingMaterial,
    ) -> Result<Self, DurableFounderRecoveryError> {
        validate_prepared_founder_supporting_material(prepared)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let session = kernel
            .session()
            .ok_or(DurableFounderRecoveryError::InvalidRecord)?;
        if session.authenticated_principal_id != prepared.authenticated_principal_id
            || session.session_id != prepared.session_id
        {
            return Err(DurableFounderRecoveryError::PrincipalMismatch);
        }
        Self::validate(MaterialRecoveryRecordV1 {
            schema: "egopulse.client-founder-material-recovery/v1".into(),
            authenticated_principal_id: prepared.authenticated_principal_id.clone(),
            projection_epoch: session.current_position.epoch.clone(),
            sealed_command_hex: hex::encode(prepared.command.encode_to_vec()),
            canonical_payload_hex: hex::encode(&prepared.capsule.canonical_payload),
        })
    }

    fn validate(record: MaterialRecoveryRecordV1) -> Result<Self, DurableFounderRecoveryError> {
        if record.schema != "egopulse.client-founder-material-recovery/v1"
            || record.authenticated_principal_id.trim().is_empty()
            || record.projection_epoch.trim().is_empty()
            || record.authenticated_principal_id.len() > 4096
            || record.projection_epoch.len() > 4096
            || (record.sealed_command_hex.len() + record.canonical_payload_hex.len()) as u64
                > MAX_RECORD_BYTES / 2
        {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        let command_bytes = hex::decode(&record.sealed_command_hex)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let payload_bytes = hex::decode(&record.canonical_payload_hex)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let command = CreateFounderSupportingMaterialCommand::decode(command_bytes.as_slice())
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let payload = FounderSupportingMaterial::decode(payload_bytes.as_slice())
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        if command.encode_to_vec() != command_bytes
            || payload.encode_to_vec() != payload_bytes
            || payload.schema_version != 1
        {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        let saved = Self {
            record,
            command,
            payload,
        };
        // Validate only frozen data here. A transport session is acquired and
        // checked separately before any send; none is stored in this record.
        let prepared = saved.prepared_for_session("")?;
        validate_prepared_founder_supporting_material(&prepared)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        Ok(saved)
    }

    fn prepared_for_session(
        &self,
        session_id: &str,
    ) -> Result<PreparedFounderSupportingMaterial, DurableFounderRecoveryError> {
        let canonical_payload = self.payload.encode_to_vec();
        let address = ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: hex::encode(Sha256::digest(&canonical_payload)),
            byte_length: canonical_payload.len() as u64,
        };
        Ok(PreparedFounderSupportingMaterial {
            command: self.command.clone(),
            session_id: session_id.into(),
            authenticated_principal_id: self.record.authenticated_principal_id.clone(),
            capsule: FounderSupportingMaterialTrustedCapsule {
                review_lineage: self
                    .payload
                    .lineage
                    .clone()
                    .ok_or(DurableFounderRecoveryError::InvalidRecord)?,
                verdict_scope: self
                    .payload
                    .scope
                    .clone()
                    .ok_or(DurableFounderRecoveryError::InvalidRecord)?,
                authenticated_founder_principal_id: self
                    .payload
                    .authenticated_founder_principal_id
                    .clone(),
                material_id: self.payload.material_id.clone(),
                role: FounderSupportingMaterialRole::try_from(self.payload.role)
                    .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?,
                body: self.payload.body.clone(),
                coverage: self.payload.coverage.clone(),
                canonical_payload,
                expected_payload_address: address,
            },
        })
    }

    pub fn task_id(&self) -> &str {
        self.payload
            .scope
            .as_ref()
            .map(|scope| scope.task_id.as_str())
            .unwrap_or_default()
    }
    pub fn material_id(&self) -> &str {
        &self.command.material_id
    }
    pub fn role(&self) -> FounderSupportingMaterialRole {
        FounderSupportingMaterialRole::try_from(self.command.role)
            .unwrap_or(FounderSupportingMaterialRole::Unspecified)
    }
    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), DurableFounderRecoveryError> {
        write_record_new(&self.record, path.as_ref())
    }
    pub fn read(path: impl AsRef<Path>) -> Result<Self, DurableFounderRecoveryError> {
        Self::validate(read_record(path.as_ref())?)
    }
}

fn write_record_new(
    record: &impl Serialize,
    path: &Path,
) -> Result<(), DurableFounderRecoveryError> {
    let bytes =
        serde_json::to_vec(record).map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(DurableFounderRecoveryError::InvalidRecord);
    }
    super::recovery_store::write_new(&bytes, path).map_err(|_| DurableFounderRecoveryError::Storage)
}

fn read_record<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, DurableFounderRecoveryError> {
    let bytes = super::recovery_store::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            DurableFounderRecoveryError::InvalidRecord
        } else {
            DurableFounderRecoveryError::Storage
        }
    })?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(DurableFounderRecoveryError::InvalidRecord);
    }
    serde_json::from_slice(&bytes).map_err(|_| DurableFounderRecoveryError::InvalidRecord)
}

impl DurableFounderVerdictRecovery {
    pub(super) fn capture(
        kernel: &ClientKernel,
        recovery: &RecoverableGuidedFounderVerdict,
    ) -> Result<Self, DurableFounderRecoveryError> {
        let session = kernel
            .session()
            .ok_or(DurableFounderRecoveryError::InvalidRecord)?;
        if session.authenticated_principal_id != recovery.authenticated_principal_id {
            return Err(DurableFounderRecoveryError::PrincipalMismatch);
        }
        Self::validate(VerdictRecoveryRecordV1 {
            schema: "egopulse.client-founder-verdict-recovery/v1".into(),
            authenticated_principal_id: recovery.authenticated_principal_id.clone(),
            projection_epoch: session.current_position.epoch.clone(),
            sealed_command_hex: hex::encode(recovery.command.encode_to_vec()),
        })
    }

    fn validate(record: VerdictRecoveryRecordV1) -> Result<Self, DurableFounderRecoveryError> {
        if record.schema != "egopulse.client-founder-verdict-recovery/v1"
            || record.authenticated_principal_id.trim().is_empty()
            || record.authenticated_principal_id.len() > 4096
            || record.projection_epoch.trim().is_empty()
            || record.projection_epoch.len() > 4096
            || record.sealed_command_hex.len() as u64 > MAX_RECORD_BYTES / 2
        {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        let bytes = hex::decode(&record.sealed_command_hex)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let command = VerdictCommand::decode(bytes.as_slice())
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        if command.encode_to_vec() != bytes {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        let issue = guided_founder_verdict_issue(&command)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let selection = match FounderVerdictDecision::try_from(issue.decision) {
            Ok(FounderVerdictDecision::Accept) => GuidedFounderVerdictSelection::Accept,
            Ok(FounderVerdictDecision::Rework) => GuidedFounderVerdictSelection::Rework,
            Ok(FounderVerdictDecision::Reject) => GuidedFounderVerdictSelection::Reject,
            _ => return Err(DurableFounderRecoveryError::InvalidRecord),
        };
        let input = guided_founder_verdict_input_from_command(&command, selection)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let scope = issue
            .scope
            .as_ref()
            .ok_or(DurableFounderRecoveryError::InvalidRecord)?;
        if input.current_task_id.trim().is_empty()
            || scope.task_revision == 0
            || scope.work_revision == 0
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
            || input.confirmation_proof_ref.trim().is_empty()
            || !guided_verdict_timestamp_is_valid(&input.expires_at)
            || validate_guided_verdict_metadata(&input.metadata).is_err()
        {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        Ok(Self {
            record,
            command,
            selection,
            source_path: None,
            apply_command: None,
        })
    }

    pub fn task_id(&self) -> &str {
        // Construction validates the Issue and scope; no mutable access exists.
        self.command
            .command
            .as_ref()
            .and_then(|command| match command {
                verdict_command::Command::IssueFounderVerdict(issue) => issue.scope.as_ref(),
                _ => None,
            })
            .map(|scope| scope.task_id.as_str())
            .unwrap_or_default()
    }

    pub fn selection(&self) -> GuidedFounderVerdictSelection {
        self.selection
    }

    pub fn command_id(&self) -> &str {
        self.command
            .command
            .as_ref()
            .and_then(|command| match command {
                verdict_command::Command::IssueFounderVerdict(issue) => issue.metadata.as_ref(),
                _ => None,
            })
            .map(|metadata| metadata.command_id.as_str())
            .unwrap_or_default()
    }

    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), DurableFounderRecoveryError> {
        write_record_new(&self.record, path.as_ref())
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self, DurableFounderRecoveryError> {
        let path = path.as_ref();
        let mut recovery = Self::validate(read_record(path)?)?;
        let apply_path = verdict_apply_recovery_path(path);
        match std::fs::metadata(&apply_path) {
            Ok(_) => {
                let apply_record: VerdictApplyRecoveryRecordV1 = read_record(&apply_path)?;
                recovery.apply_command = Some(recovery.validate_apply_record(apply_record)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DurableFounderRecoveryError::Storage),
        }
        recovery.source_path = Some(path.to_path_buf());
        Ok(recovery)
    }

    fn validate_apply_record(
        &self,
        record: VerdictApplyRecoveryRecordV1,
    ) -> Result<TaskCommand, DurableFounderRecoveryError> {
        if record.schema != "egopulse.client-founder-decision-apply-recovery/v1"
            || record.authenticated_principal_id != self.record.authenticated_principal_id
            || record.projection_epoch != self.record.projection_epoch
            || record.sealed_issue_sha256
                != hex::encode(Sha256::digest(self.command.encode_to_vec()))
            || record.sealed_apply_hex.len() as u64 > MAX_RECORD_BYTES / 2
        {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        let bytes = hex::decode(record.sealed_apply_hex)
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        let command = TaskCommand::decode(bytes.as_slice())
            .map_err(|_| DurableFounderRecoveryError::InvalidRecord)?;
        if command.encode_to_vec() != bytes
            || !matches!(
                command.command.as_ref(),
                Some(task_command::Command::ApplyFounderVerdict(_))
            )
        {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        let mut canonical = command.clone();
        set_task_digest(&mut canonical);
        if canonical != command {
            return Err(DurableFounderRecoveryError::InvalidRecord);
        }
        Ok(command)
    }

    fn write_apply_new(
        &self,
        recovery_path: &Path,
        command: &TaskCommand,
    ) -> Result<(), DurableFounderRecoveryError> {
        let record = VerdictApplyRecoveryRecordV1 {
            schema: "egopulse.client-founder-decision-apply-recovery/v1".to_owned(),
            authenticated_principal_id: self.record.authenticated_principal_id.clone(),
            projection_epoch: self.record.projection_epoch.clone(),
            sealed_issue_sha256: hex::encode(Sha256::digest(self.command.encode_to_vec())),
            sealed_apply_hex: hex::encode(command.encode_to_vec()),
        };
        self.validate_apply_record(record.clone())?;
        write_record_new(&record, &verdict_apply_recovery_path(recovery_path))
    }

    fn exact_apply_for_recovery(
        &self,
        derived: TaskCommand,
    ) -> Result<TaskCommand, DurableFounderRecoveryError> {
        if let Some(saved) = self.apply_command.as_ref() {
            if saved != &derived {
                return Err(DurableFounderRecoveryError::InvalidRecord);
            }
            return Ok(saved.clone());
        }
        let path = self
            .source_path
            .as_deref()
            .ok_or(DurableFounderRecoveryError::InvalidRecord)?;
        self.write_apply_new(path, &derived)?;
        Ok(derived)
    }
}

pub(super) fn verdict_apply_recovery_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".apply");
    PathBuf::from(value)
}

impl ClientAttachment {
    pub async fn create_founder_supporting_material_durable(
        &self,
        prepared: PreparedFounderSupportingMaterial,
        recovery_path: &Path,
    ) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
    {
        let mut client = self.connection.command_gateway_service();
        submit_durable_founder_material_via(
            &self.kernel,
            prepared,
            recovery_path,
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

    pub async fn retry_durable_founder_material(
        &self,
        recovery: &DurableFounderMaterialRecovery,
    ) -> Result<DurableFounderMaterialAttempt, DurableFounderRecoveryError> {
        let mut client = self.connection.command_gateway_service();
        retry_durable_founder_material_via(
            &self.kernel,
            recovery,
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

    /// Writes the complete sealed command before the first send. Surfaces keep
    /// this path on Unknown and can resume it after attaching a new session.
    pub async fn submit_guided_founder_verdict_durable(
        &self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
        materials: Option<&FounderSupportingMaterialCollection>,
        recovery_path: &Path,
    ) -> Result<GuidedFounderVerdictAttempt, ClientGuidedFounderVerdictError> {
        self.submit_guided_founder_verdict_inner(command, selection, materials, Some(recovery_path))
            .await
    }

    pub async fn retry_durable_founder_verdict(
        &self,
        recovery: &DurableFounderVerdictRecovery,
    ) -> Result<DurableFounderVerdictAttempt, DurableFounderRecoveryError> {
        let mut client = self.connection.command_gateway_service();
        retry_durable_founder_verdict_via(
            &self.kernel,
            recovery,
            SystemTime::now(),
            move |request| async move {
                client
                    .execute_founder_verdict(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    /// Persists the complete guided Issue capsule before any read or write RPC,
    /// then explicitly issues and applies the resulting immutable Verdict.
    pub async fn submit_guided_founder_decision_durable(
        &self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
        materials: Option<&FounderSupportingMaterialCollection>,
        recovery_path: &Path,
    ) -> Result<DurableFounderDecisionAttempt, ClientGuidedFounderVerdictError> {
        let read_client = self.connection.read_model_service();
        let evidence_client = read_client.clone();
        let mut verdict_client = self.connection.command_gateway_service();
        let mut task_client = self.connection.command_gateway_service();
        Box::pin(submit_durable_guided_founder_decision_via(
            &self.kernel,
            GuidedFounderVerdictSubmission {
                command,
                selection,
                materials,
                recovery_path: None,
            },
            recovery_path,
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
                verdict_client
                    .execute_founder_verdict(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
            move |request| async move {
                task_client
                    .execute_task_command(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        ))
        .await
    }

    /// Explicitly resumes the exact saved Issue and its deterministic Apply.
    /// It never derives a new review scope or creates a replacement command.
    pub async fn retry_durable_founder_decision(
        &self,
        recovery: &DurableFounderVerdictRecovery,
    ) -> Result<DurableFounderDecisionAttempt, DurableFounderRecoveryError> {
        let mut verdict_client = self.connection.command_gateway_service();
        let mut task_client = self.connection.command_gateway_service();
        Box::pin(retry_durable_founder_decision_via(
            &self.kernel,
            recovery,
            SystemTime::now(),
            move |request| async move {
                verdict_client
                    .execute_founder_verdict(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
            move |request| async move {
                task_client
                    .execute_task_command(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        ))
        .await
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generic seams independently prove preflight reads, Issue, and Apply ordering"
)]
pub(super) async fn submit_durable_guided_founder_decision_via<
    T,
    TFut,
    E,
    EFut,
    Issue,
    IssueFuture,
    Apply,
    ApplyFuture,
>(
    kernel: &ClientKernel,
    submission: GuidedFounderVerdictSubmission<'_>,
    recovery_path: &Path,
    now: SystemTime,
    get_task: T,
    get_evidence: E,
    send_issue: Issue,
    send_apply: Apply,
) -> Result<DurableFounderDecisionAttempt, ClientGuidedFounderVerdictError>
where
    T: FnOnce(GetTaskViewRequest) -> TFut,
    TFut: Future<Output = Result<GetTaskViewResponse, String>>,
    E: FnOnce(GetEvidenceGraphRequest) -> EFut,
    EFut: Future<Output = Result<GetEvidenceGraphResponse, String>>,
    Issue: FnOnce(ExecuteFounderVerdictRequest) -> IssueFuture,
    IssueFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
    Apply: FnOnce(ExecuteTaskCommandRequest) -> ApplyFuture,
    ApplyFuture: Future<Output = Result<ExecuteTaskCommandResponse, String>>,
{
    let GuidedFounderVerdictSubmission {
        command,
        selection,
        materials,
        recovery_path: _,
    } = submission;
    let (authenticated_principal_id, session_id) =
        authorize_guided_founder_decision_submission(kernel)?;
    validate_sealed_guided_founder_verdict(&command, selection)?;
    let recovery = RecoverableGuidedFounderVerdict {
        authenticated_principal_id,
        session_id,
        selection,
        command: command.clone(),
    };
    let saved = DurableFounderVerdictRecovery::capture(kernel, &recovery)
        .map_err(|_| ClientGuidedFounderVerdictError::InvalidInput("invalid recovery capsule"))?;
    saved
        .write_new(recovery_path)
        .map_err(|_| ClientGuidedFounderVerdictError::RecoveryStorage)?;

    // The authenticated capsule is durable before these current-view reads.
    let issue = submit_guided_founder_verdict_materials_via(
        kernel,
        GuidedFounderVerdictSubmission {
            command: command.clone(),
            selection,
            materials,
            recovery_path: None,
        },
        now,
        get_task,
        get_evidence,
        send_issue,
    )
    .await?;
    let GuidedFounderVerdictAttempt::Committed(verdict) = issue else {
        return Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Issue,
            safe_reason_code: "FOUNDER_VERDICT_ISSUE_OUTCOME_UNKNOWN",
        });
    };
    let apply = build_guided_founder_apply_command(&command, &verdict)?;
    saved
        .write_apply_new(recovery_path, &apply)
        .map_err(|_| ClientGuidedFounderVerdictError::ApplyRecoveryStorage)?;
    match dispatch_guided_founder_apply(kernel, apply, *verdict, now, send_apply).await? {
        Some(result) => Ok(DurableFounderDecisionAttempt::Applied(Box::new(result))),
        None => Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Apply,
            safe_reason_code: "FOUNDER_VERDICT_APPLY_OUTCOME_UNKNOWN",
        }),
    }
}

pub(super) async fn retry_durable_founder_decision_via<Issue, IssueFuture, Apply, ApplyFuture>(
    kernel: &ClientKernel,
    recovery: &DurableFounderVerdictRecovery,
    now: SystemTime,
    send_issue: Issue,
    send_apply: Apply,
) -> Result<DurableFounderDecisionAttempt, DurableFounderRecoveryError>
where
    Issue: FnOnce(ExecuteFounderVerdictRequest) -> IssueFuture,
    IssueFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
    Apply: FnOnce(ExecuteTaskCommandRequest) -> ApplyFuture,
    ApplyFuture: Future<Output = Result<ExecuteTaskCommandResponse, String>>,
{
    let Some(session) = kernel.session() else {
        return Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Issue,
            safe_reason_code: "RECOVERY_SESSION_UNAVAILABLE",
        });
    };
    if session.authenticated_principal_id != recovery.record.authenticated_principal_id {
        return Err(DurableFounderRecoveryError::PrincipalMismatch);
    }
    if session.current_position.epoch != recovery.record.projection_epoch {
        return Err(DurableFounderRecoveryError::StoreMismatch);
    }
    if kernel
        .profiles()
        .authorize_command(
            EXECUTE_FOUNDER_VERDICT_RPC,
            ISSUE_FOUNDER_VERDICT_COMMAND,
            &session.granted_permission_codes,
        )
        .is_err()
    {
        return Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Issue,
            safe_reason_code: "RECOVERY_CURRENT_PERMISSION_DENIED",
        });
    }
    if kernel
        .profiles()
        .authorize_command(
            EXECUTE_TASK_COMMAND_RPC,
            APPLY_FOUNDER_VERDICT_COMMAND,
            &session.granted_permission_codes,
        )
        .is_err()
    {
        return Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Apply,
            safe_reason_code: "RECOVERY_CURRENT_PERMISSION_DENIED",
        });
    }

    let verdict = match retry_durable_founder_verdict_via(kernel, recovery, now, send_issue).await?
    {
        DurableFounderVerdictAttempt::Committed(verdict) => *verdict,
        DurableFounderVerdictAttempt::Unknown { .. } => {
            return Ok(DurableFounderDecisionAttempt::Unknown {
                stage: GuidedFounderDecisionStage::Issue,
                safe_reason_code: "RECOVERY_ORIGINAL_ISSUE_OUTCOME_UNKNOWN",
            });
        }
    };
    // Once an Apply might have been sent, every later rejection or malformed
    // response remains Unknown. Only an exact committed replay resolves it.
    let Ok(derived_apply) = build_guided_founder_apply_command(&recovery.command, &verdict) else {
        return Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Apply,
            safe_reason_code: "RECOVERY_APPLY_BINDING_INVALID",
        });
    };
    let apply = recovery.exact_apply_for_recovery(derived_apply)?;
    match dispatch_guided_founder_apply(kernel, apply, verdict, now, send_apply).await {
        Ok(Some(result)) => Ok(DurableFounderDecisionAttempt::Applied(Box::new(result))),
        Ok(None) | Err(_) => Ok(DurableFounderDecisionAttempt::Unknown {
            stage: GuidedFounderDecisionStage::Apply,
            safe_reason_code: "RECOVERY_ORIGINAL_APPLY_OUTCOME_UNKNOWN",
        }),
    }
}

pub(super) async fn submit_durable_founder_material_via<Send, SendFuture>(
    kernel: &ClientKernel,
    prepared: PreparedFounderSupportingMaterial,
    recovery_path: &Path,
    now: SystemTime,
    send: Send,
) -> Result<ConfirmedFounderSupportingMaterialReceipt, ClientFounderSupportingMaterialError>
where
    Send: FnOnce(CreateFounderSupportingMaterialRequest) -> SendFuture,
    SendFuture: Future<Output = Result<CreateFounderSupportingMaterialResponse, String>>,
{
    kernel.authorize_create_founder_supporting_material()?;
    let saved = DurableFounderMaterialRecovery::capture(kernel, &prepared)
        .map_err(|_| ClientFounderSupportingMaterialError::InvalidInput)?;
    saved
        .write_new(recovery_path)
        .map_err(|_| ClientFounderSupportingMaterialError::RecoveryStorage)?;
    submit_founder_supporting_material_via(kernel, prepared, now, send).await
}

pub(super) async fn retry_durable_founder_material_via<Send, SendFuture>(
    kernel: &ClientKernel,
    recovery: &DurableFounderMaterialRecovery,
    now: SystemTime,
    send: Send,
) -> Result<DurableFounderMaterialAttempt, DurableFounderRecoveryError>
where
    Send: FnOnce(CreateFounderSupportingMaterialRequest) -> SendFuture,
    SendFuture: Future<Output = Result<CreateFounderSupportingMaterialResponse, String>>,
{
    let Some(session) = kernel.session() else {
        return Ok(DurableFounderMaterialAttempt::Unknown {
            safe_reason_code: "RECOVERY_SESSION_UNAVAILABLE",
        });
    };
    if session.authenticated_principal_id != recovery.record.authenticated_principal_id {
        return Err(DurableFounderRecoveryError::PrincipalMismatch);
    }
    if session.current_position.epoch != recovery.record.projection_epoch {
        return Err(DurableFounderRecoveryError::StoreMismatch);
    }
    if kernel
        .authorize_create_founder_supporting_material()
        .is_err()
    {
        return Ok(DurableFounderMaterialAttempt::Unknown {
            safe_reason_code: "RECOVERY_CURRENT_PERMISSION_DENIED",
        });
    }
    let prepared = recovery.prepared_for_session(&session.session_id)?;
    let correlation_id = prepared
        .command
        .metadata
        .as_ref()
        .ok_or(DurableFounderRecoveryError::InvalidRecord)?
        .correlation_id
        .clone();
    let Ok(client) = kernel.request_metadata(Uuid::now_v7().to_string(), Some(correlation_id), now)
    else {
        return Ok(DurableFounderMaterialAttempt::Unknown {
            safe_reason_code: "RECOVERY_SESSION_UNAVAILABLE",
        });
    };
    let current = RecoverableFounderSupportingMaterial {
        request: CreateFounderSupportingMaterialRequest {
            client: Some(client),
            command: Some(prepared.command.clone()),
        },
        prepared,
    };
    match dispatch_founder_supporting_material(current, send).await {
        Ok(confirmed) => Ok(DurableFounderMaterialAttempt::Confirmed(Box::new(
            confirmed,
        ))),
        Err(_) => Ok(DurableFounderMaterialAttempt::Unknown {
            safe_reason_code: "RECOVERY_ORIGINAL_OUTCOME_UNKNOWN",
        }),
    }
}

pub(super) async fn retry_durable_founder_verdict_via<Send, SendFuture>(
    kernel: &ClientKernel,
    recovery: &DurableFounderVerdictRecovery,
    now: SystemTime,
    send: Send,
) -> Result<DurableFounderVerdictAttempt, DurableFounderRecoveryError>
where
    Send: FnOnce(ExecuteFounderVerdictRequest) -> SendFuture,
    SendFuture: Future<Output = Result<ExecuteFounderVerdictResponse, String>>,
{
    let Some(session) = kernel.session() else {
        return Ok(DurableFounderVerdictAttempt::Unknown {
            safe_reason_code: "RECOVERY_SESSION_UNAVAILABLE",
        });
    };
    if session.authenticated_principal_id != recovery.record.authenticated_principal_id {
        return Err(DurableFounderRecoveryError::PrincipalMismatch);
    }
    if session.current_position.epoch != recovery.record.projection_epoch {
        return Err(DurableFounderRecoveryError::StoreMismatch);
    }
    if kernel
        .profiles()
        .authorize_command(
            EXECUTE_FOUNDER_VERDICT_RPC,
            ISSUE_FOUNDER_VERDICT_COMMAND,
            &session.granted_permission_codes,
        )
        .is_err()
    {
        return Ok(DurableFounderVerdictAttempt::Unknown {
            safe_reason_code: "RECOVERY_CURRENT_PERMISSION_DENIED",
        });
    }
    let current = RecoverableGuidedFounderVerdict {
        authenticated_principal_id: recovery.record.authenticated_principal_id.clone(),
        session_id: session.session_id.clone(),
        selection: recovery.selection,
        command: recovery.command.clone(),
    };
    // No current Task/action/expiry reconstruction: the real Authority checks
    // exact idempotency before current-scope and proof-expiry resolution.
    match dispatch_guided_founder_verdict(kernel, current, now, send).await {
        Ok(GuidedFounderVerdictAttempt::Committed(result)) => {
            Ok(DurableFounderVerdictAttempt::Committed(result))
        }
        Ok(GuidedFounderVerdictAttempt::OutcomeUnknown(_)) | Err(_) => {
            Ok(DurableFounderVerdictAttempt::Unknown {
                safe_reason_code: "RECOVERY_ORIGINAL_OUTCOME_UNKNOWN",
            })
        }
    }
}
