use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::{
    ArtifactAdmissionGuard, ArtifactAuthority, ArtifactClock, ArtifactPrincipalKind,
    AuthenticatedArtifactPrincipal, canonical_request_digest, content_address,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactStatus, ContentAddress,
        IntegrityStatus, LineageBinding, ProducerIdentity, Provenance, SealArtifactCommand,
        StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
};
use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, GovernedProcessReceipt, SupervisedProcessSpec,
    run_governed_process_outcome,
};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::repository_material::{FrozenRepositoryMaterialV1, RepositoryAcceptanceCommandV1};

const INTENT_SCHEMA: &str = "egopulse.command-execution-intent/v1";
const RECEIPT_SCHEMA: &str = "egopulse.command-execution-receipt/v1";
const RECEIPT_MAGIC: &[u8] = b"egopulse.command-execution-receipt/v1\0";
const MAX_RECEIPT_HEADER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct RepositoryCommandArtifactConfig {
    pub(crate) intent_type_ref: ContractReference,
    pub(crate) intent_transformation_ref: ContractReference,
    pub(crate) receipt_type_ref: ContractReference,
    pub(crate) receipt_transformation_ref: ContractReference,
    pub(crate) retention_profile_ref: ContractReference,
    pub(crate) supervised_runner_principal_id: String,
    pub(crate) artifact_authority_principal_id: String,
    pub(crate) component_name: String,
    pub(crate) component_version: String,
    pub(crate) sensitivity_class: String,
}

pub(crate) struct RepositoryCommandExecutionRequest<'a> {
    pub(crate) material: &'a FrozenRepositoryMaterialV1,
    pub(crate) command: &'a RepositoryAcceptanceCommandV1,
    pub(crate) lineage: LineageBinding,
    pub(crate) workspace_root: &'a Path,
    pub(crate) workspace_ref: &'a str,
    pub(crate) source_binding_ref: &'a str,
    pub(crate) input_artifact_ids: &'a [String],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryCommandBlockedReason {
    ExistingIntentWithoutReceipt,
    ArtifactAuthorityUnavailable,
    ArtifactIntegrityConflict,
    ReceiptPersistenceIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryCommandBlocked {
    pub(crate) reason: RepositoryCommandBlockedReason,
    pub(crate) lineage: LineageBinding,
    pub(crate) command_id: String,
    pub(crate) intent_artifact_id: String,
    pub(crate) receipt_artifact_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RepositoryCommandSupervisionFailure {
    InvalidSpecification,
    Spawn,
    InputDelivery,
    Timeout,
    Crashed,
    OutputLimit,
    Io,
    Protocol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryCommandReceipt {
    pub(crate) artifact_id: String,
    pub(crate) intent_artifact_id: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) supervision_failure: Option<RepositoryCommandSupervisionFailure>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) duration_ms: u64,
}

pub(crate) struct RepositoryCommandEvidenceDecodeRequest<'a> {
    pub(crate) material: &'a FrozenRepositoryMaterialV1,
    pub(crate) command: &'a RepositoryAcceptanceCommandV1,
    pub(crate) lineage: &'a LineageBinding,
    pub(crate) workspace_ref: &'a str,
    pub(crate) source_binding_ref: &'a str,
    pub(crate) expected_input_artifact_ids: &'a [String],
    pub(crate) observed_intent_input_artifact_ids: &'a [String],
    pub(crate) observed_receipt_input_artifact_ids: &'a [String],
    pub(crate) intent_bytes: &'a [u8],
    pub(crate) receipt_bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedRepositoryCommandEvidence {
    pub(crate) command_spec_sha256: String,
    pub(crate) intent_artifact_id: String,
    pub(crate) receipt_artifact_id: String,
    pub(crate) receipt: RepositoryCommandReceipt,
}

pub(crate) fn decode_repository_command_evidence(
    request: RepositoryCommandEvidenceDecodeRequest<'_>,
) -> Result<DecodedRepositoryCommandEvidence, RepositoryCommandBlockedReason> {
    let codec = prepare_command_codec(
        request.material,
        request.command,
        request.lineage,
        request.workspace_ref,
        request.source_binding_ref,
        request.expected_input_artifact_ids,
    )?;
    if request.intent_bytes != codec.intent_bytes
        || request.observed_intent_input_artifact_ids != codec.intent_input_artifact_ids
        || request.observed_receipt_input_artifact_ids != codec.receipt_input_artifact_ids
    {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let receipt = decode_receipt_parts(
        &codec.identity_digest,
        &codec.intent_artifact_id,
        &codec.intent_address,
        &codec.receipt_artifact_id,
        codec.output_limit_bytes,
        request.receipt_bytes,
    )?;
    Ok(DecodedRepositoryCommandEvidence {
        command_spec_sha256: codec.command_spec_sha256,
        intent_artifact_id: codec.intent_artifact_id,
        receipt_artifact_id: codec.receipt_artifact_id,
        receipt,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryCommandExecutionOutcome {
    Completed(RepositoryCommandReceipt),
    Replayed(RepositoryCommandReceipt),
    Blocked(RepositoryCommandBlocked),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RepositoryCommandHelperError {
    #[error("repository command helper input is invalid")]
    InvalidInput,
}

pub(crate) trait RepositoryCommandProcessExecutor: Send + Sync + 'static {
    fn execute<'a>(
        &'a self,
        spec: &'a SupervisedProcessSpec,
        budget: GovernedProcessBudget,
    ) -> Pin<
        Box<dyn Future<Output = Result<GovernedProcessReceipt, GovernedProcessError>> + Send + 'a>,
    >;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GovernedRepositoryCommandProcessExecutor;

impl RepositoryCommandProcessExecutor for GovernedRepositoryCommandProcessExecutor {
    fn execute<'a>(
        &'a self,
        spec: &'a SupervisedProcessSpec,
        budget: GovernedProcessBudget,
    ) -> Pin<
        Box<dyn Future<Output = Result<GovernedProcessReceipt, GovernedProcessError>> + Send + 'a>,
    > {
        Box::pin(run_governed_process_outcome(spec, &[], budget))
    }
}

pub(crate) struct RepositoryCommandArtifactRunner<
    G,
    C,
    E = GovernedRepositoryCommandProcessExecutor,
> {
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
    config: RepositoryCommandArtifactConfig,
    executor: E,
    execution_guard: tokio::sync::Mutex<()>,
}

impl<G, C> RepositoryCommandArtifactRunner<G, C, GovernedRepositoryCommandProcessExecutor>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    pub(crate) fn new(
        authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
        config: RepositoryCommandArtifactConfig,
    ) -> Result<Self, RepositoryCommandHelperError> {
        Self::with_executor(authority, config, GovernedRepositoryCommandProcessExecutor)
    }
}

impl<G, C, E> RepositoryCommandArtifactRunner<G, C, E>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
    E: RepositoryCommandProcessExecutor,
{
    pub(crate) fn with_executor(
        authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
        config: RepositoryCommandArtifactConfig,
        executor: E,
    ) -> Result<Self, RepositoryCommandHelperError> {
        validate_config(&config)?;
        Ok(Self {
            authority,
            config,
            executor,
            execution_guard: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) async fn execute(
        &self,
        request: RepositoryCommandExecutionRequest<'_>,
    ) -> Result<RepositoryCommandExecutionOutcome, RepositoryCommandHelperError> {
        let prepared = PreparedCommand::new(&self.config, request)?;
        let _execution_guard = self.execution_guard.lock().await;

        let preflight = {
            let mut authority = match self.authority.lock() {
                Ok(authority) => authority,
                Err(_) => {
                    return Ok(prepared
                        .blocked(RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable));
                }
            };
            inspect_or_persist_intent(&mut authority, &self.config, &prepared)
        };
        match preflight {
            Ok(IntentPreflight::Fresh) => {}
            Ok(IntentPreflight::Replay(receipt)) => {
                return Ok(RepositoryCommandExecutionOutcome::Replayed(receipt));
            }
            Ok(IntentPreflight::Blocked(reason)) | Err(reason) => {
                return Ok(prepared.blocked(reason));
            }
        }

        // The Artifact Authority lock is deliberately released before the
        // external process starts. The helper-local async mutex remains held so
        // another call in this daemon cannot mistake an in-flight command for a
        // restart orphan.
        let started_at_ms = now_millis();
        let started = Instant::now();
        let process_result = self.executor.execute(&prepared.spec, prepared.budget).await;
        let finished_at_ms = now_millis();
        let receipt = ProcessOutcome::from_result(process_result, started.elapsed());
        let receipt_bytes =
            match encode_receipt(&prepared, started_at_ms, finished_at_ms, &receipt) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(prepared
                        .blocked(RepositoryCommandBlockedReason::ReceiptPersistenceIncomplete));
                }
            };

        let persisted = {
            let mut authority = match self.authority.lock() {
                Ok(authority) => authority,
                Err(_) => {
                    return Ok(prepared
                        .blocked(RepositoryCommandBlockedReason::ReceiptPersistenceIncomplete));
                }
            };
            persist_receipt(&mut authority, &self.config, &prepared, &receipt_bytes)
        };
        match persisted {
            Ok(receipt) => Ok(RepositoryCommandExecutionOutcome::Completed(receipt)),
            Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict) => {
                Ok(prepared.blocked(RepositoryCommandBlockedReason::ArtifactIntegrityConflict))
            }
            Err(_) => {
                Ok(prepared.blocked(RepositoryCommandBlockedReason::ReceiptPersistenceIncomplete))
            }
        }
    }
}

enum IntentPreflight {
    Fresh,
    Replay(RepositoryCommandReceipt),
    Blocked(RepositoryCommandBlockedReason),
}

struct PreparedCommand {
    lineage: LineageBinding,
    command_id: String,
    workspace_ref: String,
    source_binding_ref: String,
    identity_digest: String,
    intent_artifact_id: String,
    receipt_artifact_id: String,
    intent_bytes: Vec<u8>,
    intent_address: ContentAddress,
    intent_input_artifact_ids: Vec<String>,
    receipt_input_artifact_ids: Vec<String>,
    spec: SupervisedProcessSpec,
    budget: GovernedProcessBudget,
    output_limit_bytes: u64,
}

struct PreparedCommandCodec {
    identity_digest: String,
    intent_artifact_id: String,
    receipt_artifact_id: String,
    intent_bytes: Vec<u8>,
    intent_address: ContentAddress,
    intent_input_artifact_ids: Vec<String>,
    receipt_input_artifact_ids: Vec<String>,
    command_spec_sha256: String,
    output_limit_bytes: u64,
}

impl PreparedCommand {
    fn new(
        _config: &RepositoryCommandArtifactConfig,
        request: RepositoryCommandExecutionRequest<'_>,
    ) -> Result<Self, RepositoryCommandHelperError> {
        if !lineage_valid(&request.lineage)
            || request.workspace_ref.trim().is_empty()
            || request.source_binding_ref.trim().is_empty()
            || request.input_artifact_ids.is_empty()
            || request
                .input_artifact_ids
                .iter()
                .any(|value| value.trim().is_empty())
            || !request
                .material
                .acceptance_contract
                .required_commands
                .iter()
                .any(|candidate| candidate == request.command)
            || request.command.timeout_seconds == 0
            || request.command.output_limit_bytes == 0
        {
            return Err(RepositoryCommandHelperError::InvalidInput);
        }
        let workspace_root = request
            .workspace_root
            .canonicalize()
            .map_err(|_| RepositoryCommandHelperError::InvalidInput)?;
        let working_directory = if request.command.cwd == "." {
            workspace_root.clone()
        } else {
            workspace_root.join(&request.command.cwd)
        }
        .canonicalize()
        .map_err(|_| RepositoryCommandHelperError::InvalidInput)?;
        if !working_directory.starts_with(&workspace_root) || !working_directory.is_dir() {
            return Err(RepositoryCommandHelperError::InvalidInput);
        }

        let codec = prepare_command_codec(
            request.material,
            request.command,
            &request.lineage,
            request.workspace_ref,
            request.source_binding_ref,
            request.input_artifact_ids,
        )
        .map_err(|_| RepositoryCommandHelperError::InvalidInput)?;

        let mut spec = SupervisedProcessSpec::new(&request.command.executable, working_directory);
        spec.arguments.clone_from(&request.command.argv);
        spec.clear_environment = true;
        spec.inherited_environment
            .clone_from(&request.command.inherited_environment);
        spec.environment_overrides = request
            .command
            .environment_overrides
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();

        Ok(Self {
            lineage: request.lineage,
            command_id: request.command.command_id.clone(),
            workspace_ref: request.workspace_ref.to_owned(),
            source_binding_ref: request.source_binding_ref.to_owned(),
            identity_digest: codec.identity_digest,
            intent_artifact_id: codec.intent_artifact_id,
            receipt_artifact_id: codec.receipt_artifact_id,
            intent_bytes: codec.intent_bytes,
            intent_address: codec.intent_address,
            intent_input_artifact_ids: codec.intent_input_artifact_ids,
            receipt_input_artifact_ids: codec.receipt_input_artifact_ids,
            spec,
            budget: GovernedProcessBudget {
                timeout: Duration::from_secs(request.command.timeout_seconds),
                output_limit_bytes: request.command.output_limit_bytes,
            },
            output_limit_bytes: request.command.output_limit_bytes,
        })
    }

    fn blocked(&self, reason: RepositoryCommandBlockedReason) -> RepositoryCommandExecutionOutcome {
        RepositoryCommandExecutionOutcome::Blocked(RepositoryCommandBlocked {
            reason,
            lineage: self.lineage.clone(),
            command_id: self.command_id.clone(),
            intent_artifact_id: self.intent_artifact_id.clone(),
            receipt_artifact_id: self.receipt_artifact_id.clone(),
        })
    }
}

fn prepare_command_codec(
    material: &FrozenRepositoryMaterialV1,
    command: &RepositoryAcceptanceCommandV1,
    lineage: &LineageBinding,
    workspace_ref: &str,
    source_binding_ref: &str,
    input_artifact_ids: &[String],
) -> Result<PreparedCommandCodec, RepositoryCommandBlockedReason> {
    if !lineage_valid(lineage)
        || workspace_ref.trim().is_empty()
        || source_binding_ref.trim().is_empty()
        || input_artifact_ids.is_empty()
        || input_artifact_ids
            .iter()
            .any(|value| value.trim().is_empty())
        || !material
            .acceptance_contract
            .required_commands
            .iter()
            .any(|candidate| candidate == command)
        || command.timeout_seconds == 0
        || command.output_limit_bytes == 0
    {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let identity = CommandIdentity::new(material, command, lineage);
    let identity_bytes = serde_json::to_vec(&identity)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let identity_digest = sha256(&identity_bytes);
    let intent_artifact_id = format!("artifact:repository-command-intent:{identity_digest}");
    let receipt_artifact_id = format!("artifact:repository-command-receipt:{identity_digest}");
    let command_bytes = serde_json::to_vec(command)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let command_spec_sha256 = sha256(&command_bytes);
    let intent = CommandIntentPayload {
        schema: INTENT_SCHEMA,
        identity,
        command_spec_sha256: command_spec_sha256.clone(),
        workspace_ref,
        source_binding_ref,
        baseline_commit: &material.baseline_commit,
        baseline_tree: &material.baseline_tree,
        timeout_seconds: command.timeout_seconds,
        output_limit_bytes: command.output_limit_bytes,
        expected_exit_code: command.expected_exit_code,
        inherited_environment_names: &command.inherited_environment,
        environment_override_names: command
            .environment_overrides
            .keys()
            .map(String::as_str)
            .collect(),
    };
    let intent_bytes = serde_json::to_vec(&intent)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let intent_address = content_address(&intent_bytes);
    let intent_input_artifact_ids = input_artifact_ids.to_vec();
    let mut receipt_input_artifact_ids = intent_input_artifact_ids.clone();
    receipt_input_artifact_ids.push(intent_artifact_id.clone());
    Ok(PreparedCommandCodec {
        identity_digest,
        intent_artifact_id,
        receipt_artifact_id,
        intent_bytes,
        intent_address,
        intent_input_artifact_ids,
        receipt_input_artifact_ids,
        command_spec_sha256,
        output_limit_bytes: command.output_limit_bytes,
    })
}

#[derive(Serialize)]
struct CommandIntentPayload<'a> {
    schema: &'static str,
    identity: CommandIdentity<'a>,
    command_spec_sha256: String,
    workspace_ref: &'a str,
    source_binding_ref: &'a str,
    baseline_commit: &'a str,
    baseline_tree: &'a str,
    timeout_seconds: u64,
    output_limit_bytes: u64,
    expected_exit_code: i32,
    inherited_environment_names: &'a [String],
    environment_override_names: Vec<&'a str>,
}

#[derive(Serialize)]
struct CommandIdentity<'a> {
    task_id: &'a str,
    task_revision: u64,
    work_revision: u64,
    run_id: &'a str,
    run_revision: u64,
    step_id: &'a str,
    step_revision: u64,
    attempt_id: &'a str,
    attempt_revision: u64,
    dispatch_id: &'a str,
    fencing_token: u64,
    acceptance_contract_id: &'a str,
    acceptance_contract_version: &'a str,
    acceptance_contract_sha256: &'a str,
    command_id: &'a str,
    criterion_id: &'a str,
}

impl<'a> CommandIdentity<'a> {
    fn new(
        material: &'a FrozenRepositoryMaterialV1,
        command: &'a RepositoryAcceptanceCommandV1,
        lineage: &'a LineageBinding,
    ) -> Self {
        Self {
            task_id: &lineage.task_id,
            task_revision: lineage.task_revision,
            work_revision: lineage.work_revision,
            run_id: &lineage.run_id,
            run_revision: lineage.run_revision,
            step_id: &lineage.step_id,
            step_revision: lineage.step_revision,
            attempt_id: &lineage.attempt_id,
            attempt_revision: lineage.attempt_revision,
            dispatch_id: &lineage.dispatch_id,
            fencing_token: lineage.fencing_token,
            acceptance_contract_id: &material.acceptance_contract_ref.contract_id,
            acceptance_contract_version: &material.acceptance_contract_ref.version,
            acceptance_contract_sha256: &material.acceptance_contract_ref.sha256,
            command_id: &command.command_id,
            criterion_id: &command.criterion_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ReceiptHeader {
    schema: String,
    identity_sha256: String,
    intent_artifact_id: String,
    intent_content_sha256: String,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    duration_ms: u64,
    exit_code: Option<i32>,
    supervision_failure: Option<RepositoryCommandSupervisionFailure>,
    stdout_available: bool,
    stdout_sha256: String,
    stdout_byte_length: u64,
    stderr_available: bool,
    stderr_sha256: String,
    stderr_byte_length: u64,
    output_limit_bytes: u64,
}

struct ProcessOutcome {
    exit_code: Option<i32>,
    failure: Option<RepositoryCommandSupervisionFailure>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_ms: u64,
    output_available: bool,
}

impl ProcessOutcome {
    fn from_result(
        result: Result<GovernedProcessReceipt, GovernedProcessError>,
        elapsed: Duration,
    ) -> Self {
        match result {
            Ok(receipt) => Self {
                exit_code: Some(receipt.exit_code),
                failure: None,
                stdout: receipt.stdout,
                stderr: receipt.stderr,
                duration_ms: receipt.duration_ms,
                output_available: true,
            },
            Err(error) => Self {
                exit_code: None,
                failure: Some(map_process_error(error)),
                stdout: Vec::new(),
                stderr: Vec::new(),
                duration_ms: elapsed.as_millis().try_into().unwrap_or(u64::MAX),
                output_available: false,
            },
        }
    }
}

fn inspect_or_persist_intent<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &RepositoryCommandArtifactConfig,
    prepared: &PreparedCommand,
) -> Result<IntentPreflight, RepositoryCommandBlockedReason>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let receipt = authority
        .read_artifact(&prepared.receipt_artifact_id)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    let intent = authority
        .read_artifact(&prepared.intent_artifact_id)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    if let Some(receipt) = receipt {
        let Some(intent) = intent else {
            return Ok(IntentPreflight::Blocked(
                RepositoryCommandBlockedReason::ArtifactIntegrityConflict,
            ));
        };
        validate_artifact(
            authority,
            &intent,
            prepared,
            config,
            ArtifactKind::Intent,
            Some(&prepared.intent_bytes),
        )?;
        if intent.status != ArtifactStatus::Sealed as i32 {
            return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
        }
        let decoded = validate_artifact(
            authority,
            &receipt,
            prepared,
            config,
            ArtifactKind::Receipt,
            None,
        )?
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
        if receipt.status == ArtifactStatus::Staged as i32 {
            let address = receipt
                .content
                .clone()
                .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
            let result = authority
                .execute(
                    &seal_command(prepared, &receipt.artifact_id, address, "seal-receipt"),
                    &principal(
                        ArtifactPrincipalKind::ArtifactAuthority,
                        &config.artifact_authority_principal_id,
                    ),
                )
                .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
            if !result.committed {
                return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
            }
            let sealed = authority
                .read_artifact(&prepared.receipt_artifact_id)
                .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?
                .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
            validate_artifact(
                authority,
                &sealed,
                prepared,
                config,
                ArtifactKind::Receipt,
                None,
            )?;
            if sealed.status != ArtifactStatus::Sealed as i32 {
                return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
            }
        }
        return Ok(IntentPreflight::Replay(decoded));
    }
    if let Some(intent) = intent {
        validate_artifact(
            authority,
            &intent,
            prepared,
            config,
            ArtifactKind::Intent,
            Some(&prepared.intent_bytes),
        )?;
        return Ok(IntentPreflight::Blocked(
            RepositoryCommandBlockedReason::ExistingIntentWithoutReceipt,
        ));
    }

    authority
        .put_blob(&prepared.intent_bytes, &prepared.intent_address)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    let artifact = artifact_descriptor(
        prepared,
        config,
        ArtifactKind::Intent,
        prepared.intent_address.clone(),
    );
    let staged = authority
        .execute(
            &stage_command(prepared, artifact, "stage-intent"),
            &principal(
                ArtifactPrincipalKind::SupervisedRunner,
                &config.supervised_runner_principal_id,
            ),
        )
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    if !staged.committed || staged.replayed {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let sealed = authority
        .execute(
            &seal_command(
                prepared,
                &prepared.intent_artifact_id,
                prepared.intent_address.clone(),
                "seal-intent",
            ),
            &principal(
                ArtifactPrincipalKind::ArtifactAuthority,
                &config.artifact_authority_principal_id,
            ),
        )
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    if !sealed.committed || sealed.replayed {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let current = authority
        .read_artifact(&prepared.intent_artifact_id)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    validate_artifact(
        authority,
        &current,
        prepared,
        config,
        ArtifactKind::Intent,
        Some(&prepared.intent_bytes),
    )?;
    if current.status != ArtifactStatus::Sealed as i32 {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    Ok(IntentPreflight::Fresh)
}

fn persist_receipt<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &RepositoryCommandArtifactConfig,
    prepared: &PreparedCommand,
    bytes: &[u8],
) -> Result<RepositoryCommandReceipt, RepositoryCommandBlockedReason>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let address = content_address(bytes);
    authority
        .put_blob(bytes, &address)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    let artifact = artifact_descriptor(prepared, config, ArtifactKind::Receipt, address.clone());
    let staged = authority
        .execute(
            &stage_command(prepared, artifact, "stage-receipt"),
            &principal(
                ArtifactPrincipalKind::SupervisedRunner,
                &config.supervised_runner_principal_id,
            ),
        )
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    if !staged.committed || staged.replayed {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let sealed = authority
        .execute(
            &seal_command(
                prepared,
                &prepared.receipt_artifact_id,
                address,
                "seal-receipt",
            ),
            &principal(
                ArtifactPrincipalKind::ArtifactAuthority,
                &config.artifact_authority_principal_id,
            ),
        )
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    if !sealed.committed || sealed.replayed {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let current = authority
        .read_artifact(&prepared.receipt_artifact_id)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let decoded = validate_artifact(
        authority,
        &current,
        prepared,
        config,
        ArtifactKind::Receipt,
        Some(bytes),
    )?
    .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    if current.status != ArtifactStatus::Sealed as i32 {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    Ok(decoded)
}

#[derive(Clone, Copy)]
enum ArtifactKind {
    Intent,
    Receipt,
}

fn artifact_descriptor(
    prepared: &PreparedCommand,
    config: &RepositoryCommandArtifactConfig,
    kind: ArtifactKind,
    address: ContentAddress,
) -> ArtifactDescriptor {
    let (artifact_id, semantic_class, type_ref, transformation_ref, media_type, inputs, source) =
        match kind {
            ArtifactKind::Intent => (
                prepared.intent_artifact_id.clone(),
                ArtifactSemanticClass::TypedExtension,
                config.intent_type_ref.clone(),
                config.intent_transformation_ref.clone(),
                "application/json",
                prepared.intent_input_artifact_ids.clone(),
                prepared.source_binding_ref.clone(),
            ),
            ArtifactKind::Receipt => (
                prepared.receipt_artifact_id.clone(),
                ArtifactSemanticClass::CommandReceipt,
                config.receipt_type_ref.clone(),
                config.receipt_transformation_ref.clone(),
                "application/vnd.egopulse.command-execution-receipt.v1",
                prepared.receipt_input_artifact_ids.clone(),
                prepared.source_binding_ref.clone(),
            ),
        };
    ArtifactDescriptor {
        artifact_id,
        revision: 1,
        status: ArtifactStatus::Staged as i32,
        semantic_class: semantic_class as i32,
        type_contract_ref: Some(type_ref),
        media_type: media_type.to_owned(),
        content: Some(address),
        integrity_status: IntegrityStatus::Unverified as i32,
        provenance: Some(Provenance {
            lineage: Some(prepared.lineage.clone()),
            producer: Some(ProducerIdentity {
                principal_kind: ArtifactPrincipalKind::SupervisedRunner.as_str().to_owned(),
                principal_id: config.supervised_runner_principal_id.clone(),
                component_name: config.component_name.clone(),
                component_version: config.component_version.clone(),
                capability_profile_id: None,
                native_execution_ref: None,
            }),
            input_artifact_ids: inputs,
            transformation_contract_ref: Some(transformation_ref),
            workspace_ref: prepared.workspace_ref.clone(),
            observed_at: None,
            captured_at: None,
            raw_source_ref: Some(source),
        }),
        sensitivity_class: config.sensitivity_class.clone(),
        retention_profile_ref: Some(config.retention_profile_ref.clone()),
        created_at: None,
        sealed_at: None,
        supersedes_artifact_id: None,
        quarantine_reason_code: None,
    }
}

fn validate_artifact<G, C>(
    authority: &ArtifactAuthority<G, C>,
    artifact: &ArtifactDescriptor,
    prepared: &PreparedCommand,
    config: &RepositoryCommandArtifactConfig,
    kind: ArtifactKind,
    exact_bytes: Option<&[u8]>,
) -> Result<Option<RepositoryCommandReceipt>, RepositoryCommandBlockedReason>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    if artifact.status != ArtifactStatus::Staged as i32
        && artifact.status != ArtifactStatus::Sealed as i32
    {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    if artifact.integrity_status != IntegrityStatus::DigestVerified as i32 {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let address = artifact
        .content
        .as_ref()
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let expected = artifact_descriptor(prepared, config, kind, address.clone());
    let actual_provenance = artifact
        .provenance
        .as_ref()
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let expected_provenance = expected
        .provenance
        .as_ref()
        .expect("constructed descriptor has provenance");
    if artifact.artifact_id != expected.artifact_id
        || artifact.semantic_class != expected.semantic_class
        || artifact.type_contract_ref != expected.type_contract_ref
        || artifact.media_type != expected.media_type
        || artifact.sensitivity_class != expected.sensitivity_class
        || artifact.retention_profile_ref != expected.retention_profile_ref
        || actual_provenance.lineage != expected_provenance.lineage
        || actual_provenance.producer != expected_provenance.producer
        || actual_provenance.input_artifact_ids != expected_provenance.input_artifact_ids
        || actual_provenance.transformation_contract_ref
            != expected_provenance.transformation_contract_ref
        || actual_provenance.workspace_ref != expected_provenance.workspace_ref
        || actual_provenance.raw_source_ref != expected_provenance.raw_source_ref
    {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let bytes = authority
        .read_blob(address)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable)?;
    if content_address(&bytes) != *address
        || exact_bytes.is_some_and(|expected| expected != bytes.as_slice())
    {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    match kind {
        ArtifactKind::Intent => {
            if bytes != prepared.intent_bytes {
                return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
            }
            Ok(None)
        }
        ArtifactKind::Receipt => decode_receipt(prepared, &bytes).map(Some),
    }
}

fn encode_receipt(
    prepared: &PreparedCommand,
    started_at_ms: u64,
    finished_at_ms: u64,
    outcome: &ProcessOutcome,
) -> Result<Vec<u8>, serde_json::Error> {
    let header = ReceiptHeader {
        schema: RECEIPT_SCHEMA.to_owned(),
        identity_sha256: prepared.identity_digest.clone(),
        intent_artifact_id: prepared.intent_artifact_id.clone(),
        intent_content_sha256: prepared.intent_address.digest.clone(),
        started_at_unix_ms: started_at_ms,
        finished_at_unix_ms: finished_at_ms,
        duration_ms: outcome.duration_ms,
        exit_code: outcome.exit_code,
        supervision_failure: outcome.failure,
        stdout_available: outcome.output_available,
        stdout_sha256: sha256(&outcome.stdout),
        stdout_byte_length: outcome.stdout.len() as u64,
        stderr_available: outcome.output_available,
        stderr_sha256: sha256(&outcome.stderr),
        stderr_byte_length: outcome.stderr.len() as u64,
        output_limit_bytes: prepared.output_limit_bytes,
    };
    let header = serde_json::to_vec(&header)?;
    let mut bytes = Vec::with_capacity(
        RECEIPT_MAGIC.len() + 8 + header.len() + outcome.stdout.len() + outcome.stderr.len(),
    );
    bytes.extend_from_slice(RECEIPT_MAGIC);
    bytes.extend_from_slice(&(header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&outcome.stdout);
    bytes.extend_from_slice(&outcome.stderr);
    Ok(bytes)
}

fn decode_receipt(
    prepared: &PreparedCommand,
    bytes: &[u8],
) -> Result<RepositoryCommandReceipt, RepositoryCommandBlockedReason> {
    decode_receipt_parts(
        &prepared.identity_digest,
        &prepared.intent_artifact_id,
        &prepared.intent_address,
        &prepared.receipt_artifact_id,
        prepared.output_limit_bytes,
        bytes,
    )
}

fn decode_receipt_parts(
    identity_digest: &str,
    intent_artifact_id: &str,
    intent_address: &ContentAddress,
    receipt_artifact_id: &str,
    output_limit_bytes: u64,
    bytes: &[u8],
) -> Result<RepositoryCommandReceipt, RepositoryCommandBlockedReason> {
    let prefix_len = RECEIPT_MAGIC.len() + 8;
    if bytes.len() < prefix_len || &bytes[..RECEIPT_MAGIC.len()] != RECEIPT_MAGIC {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let header_len = u64::from_be_bytes(
        bytes[RECEIPT_MAGIC.len()..prefix_len]
            .try_into()
            .map_err(|_| RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?,
    ) as usize;
    if header_len == 0 || header_len > MAX_RECEIPT_HEADER_BYTES {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let header_end = prefix_len
        .checked_add(header_len)
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let header_bytes = bytes
        .get(prefix_len..header_end)
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let header: ReceiptHeader = serde_json::from_slice(header_bytes)
        .map_err(|_| RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    if header.schema != RECEIPT_SCHEMA
        || header.identity_sha256 != identity_digest
        || header.intent_artifact_id != intent_artifact_id
        || header.intent_content_sha256 != intent_address.digest
        || header.output_limit_bytes != output_limit_bytes
        || header.stdout_byte_length > output_limit_bytes
        || header.stderr_byte_length > output_limit_bytes
        || (header.exit_code.is_some() == header.supervision_failure.is_some())
        || (header.exit_code.is_some() && (!header.stdout_available || !header.stderr_available))
        || (header.supervision_failure.is_some()
            && (header.stdout_available
                || header.stderr_available
                || header.stdout_byte_length != 0
                || header.stderr_byte_length != 0))
    {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let stdout_end = header_end
        .checked_add(header.stdout_byte_length as usize)
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    let stderr_end = stdout_end
        .checked_add(header.stderr_byte_length as usize)
        .ok_or(RepositoryCommandBlockedReason::ArtifactIntegrityConflict)?;
    if stderr_end != bytes.len() {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    let stdout = bytes[header_end..stdout_end].to_vec();
    let stderr = bytes[stdout_end..stderr_end].to_vec();
    if sha256(&stdout) != header.stdout_sha256 || sha256(&stderr) != header.stderr_sha256 {
        return Err(RepositoryCommandBlockedReason::ArtifactIntegrityConflict);
    }
    Ok(RepositoryCommandReceipt {
        artifact_id: receipt_artifact_id.to_owned(),
        intent_artifact_id: intent_artifact_id.to_owned(),
        exit_code: header.exit_code,
        supervision_failure: header.supervision_failure,
        stdout,
        stderr,
        duration_ms: header.duration_ms,
    })
}

fn stage_command(
    prepared: &PreparedCommand,
    candidate: ArtifactDescriptor,
    operation: &str,
) -> ArtifactCommand {
    command_with_digest(artifact_command::Command::StageArtifact(
        StageArtifactCommand {
            metadata: Some(metadata(prepared, operation)),
            candidate: Some(candidate),
        },
    ))
}

fn seal_command(
    prepared: &PreparedCommand,
    artifact_id: &str,
    observed_content: ContentAddress,
    operation: &str,
) -> ArtifactCommand {
    command_with_digest(artifact_command::Command::SealArtifact(
        SealArtifactCommand {
            metadata: Some(metadata(prepared, operation)),
            artifact_id: artifact_id.to_owned(),
            expected_revision: 1,
            observed_content: Some(observed_content),
        },
    ))
}

fn command_with_digest(command: artifact_command::Command) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(command),
    };
    let digest = canonical_request_digest(&command).expect("Artifact command is present");
    match command
        .command
        .as_mut()
        .expect("Artifact command is present")
    {
        artifact_command::Command::StageArtifact(value) => {
            value
                .metadata
                .as_mut()
                .expect("metadata is present")
                .request_digest_sha256 = digest;
        }
        artifact_command::Command::SealArtifact(value) => {
            value
                .metadata
                .as_mut()
                .expect("metadata is present")
                .request_digest_sha256 = digest;
        }
        _ => unreachable!("repository command helper only stages and seals Artifacts"),
    }
    command
}

fn metadata(prepared: &PreparedCommand, operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!(
            "repository-command:{operation}:{}",
            prepared.identity_digest
        ),
        idempotency_key: format!(
            "repository-command/v1/{operation}/{}",
            prepared.identity_digest
        ),
        idempotency_scope: format!("repository-command/v1/{}", prepared.identity_digest),
        request_digest_sha256: String::new(),
        issued_at: Some(now_timestamp()),
        correlation_id: prepared.lineage.dispatch_id.clone(),
        causation_id: Some(prepared.command_id.clone()),
    }
}

fn principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn validate_config(
    config: &RepositoryCommandArtifactConfig,
) -> Result<(), RepositoryCommandHelperError> {
    if !contract_ref_valid(&config.intent_type_ref)
        || !contract_ref_valid(&config.intent_transformation_ref)
        || !contract_ref_valid(&config.receipt_type_ref)
        || !contract_ref_valid(&config.receipt_transformation_ref)
        || !contract_ref_valid(&config.retention_profile_ref)
        || config.intent_type_ref == config.receipt_type_ref
        || config.supervised_runner_principal_id.trim().is_empty()
        || config.artifact_authority_principal_id.trim().is_empty()
        || config.component_name.trim().is_empty()
        || config.component_version.trim().is_empty()
        || config.sensitivity_class.trim().is_empty()
    {
        return Err(RepositoryCommandHelperError::InvalidInput);
    }
    Ok(())
}

fn contract_ref_valid(value: &ContractReference) -> bool {
    !value.contract_id.trim().is_empty()
        && !value.version.trim().is_empty()
        && value.sha256.len() == 64
        && value
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lineage_valid(value: &LineageBinding) -> bool {
    !value.task_id.trim().is_empty()
        && value.task_revision > 0
        && value.work_revision > 0
        && !value.run_id.trim().is_empty()
        && value.run_revision > 0
        && !value.step_id.trim().is_empty()
        && value.step_revision > 0
        && !value.attempt_id.trim().is_empty()
        && value.attempt_revision > 0
        && !value.dispatch_id.trim().is_empty()
        && value.fencing_token > 0
}

fn map_process_error(error: GovernedProcessError) -> RepositoryCommandSupervisionFailure {
    match error {
        GovernedProcessError::InvalidSpecification => {
            RepositoryCommandSupervisionFailure::InvalidSpecification
        }
        GovernedProcessError::Spawn => RepositoryCommandSupervisionFailure::Spawn,
        GovernedProcessError::InputDelivery => RepositoryCommandSupervisionFailure::InputDelivery,
        GovernedProcessError::Timeout => RepositoryCommandSupervisionFailure::Timeout,
        GovernedProcessError::Crashed => RepositoryCommandSupervisionFailure::Crashed,
        GovernedProcessError::OutputLimit => RepositoryCommandSupervisionFailure::OutputLimit,
        GovernedProcessError::Io => RepositoryCommandSupervisionFailure::Io,
        GovernedProcessError::Protocol => RepositoryCommandSupervisionFailure::Protocol,
    }
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: duration.as_secs().try_into().unwrap_or(i64::MAX),
        nanos: duration.subsec_nanos().try_into().unwrap_or_default(),
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::path::PathBuf;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use egopulse_artifact_authority::{
        AdmissionRejection, ArtifactAuthorityConfig, ArtifactSqlCipherKey, SystemArtifactClock,
    };
    use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
        ArtifactSet, Claim, Evidence, ReturnHandoff,
    };
    use tempfile::TempDir;

    use crate::repository_material::{
        FrozenContractReference, RepositoryAcceptanceContractV1, RepositoryCommandRequirement,
        RepositoryEvidenceRequirement,
    };

    #[derive(Clone)]
    struct AllowFixture;

    impl ArtifactAdmissionGuard for AllowFixture {
        fn validate_artifact(
            &self,
            _artifact: &ArtifactDescriptor,
            bytes: &[u8],
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            if bytes.windows(13).any(|window| window == b"fixture-secret") {
                return Err(AdmissionRejection::SecretDetected);
            }
            Ok(())
        }

        fn validate_claim(
            &self,
            _claim: &Claim,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }

        fn validate_evidence(
            &self,
            _evidence: &Evidence,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }

        fn validate_artifact_set(
            &self,
            _artifact_set: &ArtifactSet,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }

        fn validate_return_handoff(
            &self,
            _handoff: &ReturnHandoff,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeExecutor {
        calls: Arc<AtomicUsize>,
        result: Result<GovernedProcessReceipt, RepositoryCommandSupervisionFailure>,
    }

    #[derive(Clone)]
    struct GateExecutor {
        calls: Arc<AtomicUsize>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl RepositoryCommandProcessExecutor for GateExecutor {
        fn execute<'a>(
            &'a self,
            _spec: &'a SupervisedProcessSpec,
            _budget: GovernedProcessBudget,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GovernedProcessReceipt, GovernedProcessError>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
                Ok(GovernedProcessReceipt {
                    stdout: b"one execution".to_vec(),
                    stderr: Vec::new(),
                    exit_code: 0,
                    duration_ms: 1,
                })
            })
        }
    }

    impl RepositoryCommandProcessExecutor for FakeExecutor {
        fn execute<'a>(
            &'a self,
            _spec: &'a SupervisedProcessSpec,
            _budget: GovernedProcessBudget,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GovernedProcessReceipt, GovernedProcessError>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.result.clone();
            Box::pin(async move { result.map_err(unmap_process_error) })
        }
    }

    struct Fixture {
        root: TempDir,
        authority: Arc<Mutex<ArtifactAuthority<AllowFixture>>>,
        material: FrozenRepositoryMaterialV1,
        command: RepositoryAcceptanceCommandV1,
        config: RepositoryCommandArtifactConfig,
        lineage: LineageBinding,
        input_artifact_ids: Vec<String>,
    }

    type FixtureAuthority = ArtifactAuthority<AllowFixture, SystemArtifactClock>;

    fn open_fixture_authority(root: &Path, label: &str) -> Arc<Mutex<FixtureAuthority>> {
        Arc::new(Mutex::new(
            ArtifactAuthority::open(
                ArtifactAuthorityConfig {
                    database_path: root.join("artifact.db"),
                    blob_root: root.join("blobs"),
                    store_epoch: format!("repository-command-{label}"),
                    key: ArtifactSqlCipherKey::new([0x71; 32]),
                },
                AllowFixture,
            )
            .expect("Artifact Authority"),
        ))
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = tempfile::Builder::new()
                .prefix(&format!("repository-command-{label}-"))
                .tempdir()
                .expect("fixture root");
            let workspace = root.path().join("workspace");
            std::fs::create_dir_all(&workspace).expect("workspace");
            let command = RepositoryAcceptanceCommandV1 {
                command_id: "tests-1".to_owned(),
                criterion_id: "tests".to_owned(),
                requirement: RepositoryCommandRequirement::MustPass,
                executable: root
                    .path()
                    .join("fixture-command.exe")
                    .display()
                    .to_string(),
                argv: vec!["--safe-fixture".to_owned()],
                cwd: ".".to_owned(),
                inherited_environment: vec!["PATH".to_owned()],
                environment_overrides: BTreeMap::from([(
                    "FIXTURE_MODE".to_owned(),
                    "safe".to_owned(),
                )]),
                timeout_seconds: 5,
                output_limit_bytes: 1024,
                expected_exit_code: 0,
            };
            let material = FrozenRepositoryMaterialV1 {
                schema_version: "egopulse.repository-material/v1".to_owned(),
                contract_path: root.path().join("acceptance.json").display().to_string(),
                repository_root: workspace.display().to_string(),
                git_executable: root.path().join("git.exe").display().to_string(),
                acceptance_contract_ref: FrozenContractReference {
                    contract_id: "acceptance".to_owned(),
                    version: "v1".to_owned(),
                    sha256: "ab".repeat(32),
                },
                acceptance_contract: RepositoryAcceptanceContractV1 {
                    schema_version: "repository_change_acceptance/v1".to_owned(),
                    contract_id: "acceptance".to_owned(),
                    version: "v1".to_owned(),
                    revision: 1,
                    allowed_paths: vec!["src".to_owned()],
                    forbidden_paths: Vec::new(),
                    read_only_paths: Vec::new(),
                    required_commands: vec![command.clone()],
                    evidence_requirements: vec![
                        RepositoryEvidenceRequirement::RepositoryBaseline,
                        RepositoryEvidenceRequirement::RepositoryPatch,
                        RepositoryEvidenceRequirement::WorkspaceManifest,
                        RepositoryEvidenceRequirement::CommandReceipt,
                        RepositoryEvidenceRequirement::IndependentChecker,
                    ],
                },
                baseline_commit: "cd".repeat(20),
                baseline_tree: "ef".repeat(20),
                git_common_dir: root.path().join("git-common").display().to_string(),
                clean_worktree: true,
            };
            let config = RepositoryCommandArtifactConfig {
                intent_type_ref: reference("command-execution-intent", 0x11),
                intent_transformation_ref: reference("capture-command-intent", 0x22),
                receipt_type_ref: reference("command-execution-receipt", 0x33),
                receipt_transformation_ref: reference("capture-command-receipt", 0x44),
                retention_profile_ref: reference("repository-evidence-retention", 0x55),
                supervised_runner_principal_id: "runner:repository-command".to_owned(),
                artifact_authority_principal_id: "authority:artifact".to_owned(),
                component_name: "agentosd-repository-command".to_owned(),
                component_version: "0.1.0".to_owned(),
                sensitivity_class: "local-user-data".to_owned(),
            };
            let authority = open_fixture_authority(root.path(), label);
            Self {
                root,
                authority,
                material,
                command,
                config,
                lineage: LineageBinding {
                    task_id: "task-1".to_owned(),
                    task_revision: 2,
                    work_revision: 1,
                    run_id: "run-1".to_owned(),
                    run_revision: 3,
                    step_id: "step-1".to_owned(),
                    step_revision: 4,
                    attempt_id: "attempt-1".to_owned(),
                    attempt_revision: 5,
                    dispatch_id: "dispatch-1".to_owned(),
                    fencing_token: 6,
                },
                input_artifact_ids: vec!["artifact:baseline:dispatch-1".to_owned()],
            }
        }

        fn request(&self) -> RepositoryCommandExecutionRequest<'_> {
            RepositoryCommandExecutionRequest {
                material: &self.material,
                command: &self.command,
                lineage: self.lineage.clone(),
                workspace_root: Path::new(&self.material.repository_root),
                workspace_ref: "workspace:task-1",
                source_binding_ref: "repository-test://task-1",
                input_artifact_ids: &self.input_artifact_ids,
            }
        }

        fn prepared(&self) -> PreparedCommand {
            PreparedCommand::new(&self.config, self.request()).expect("prepared command")
        }
    }

    #[cfg(windows)]
    fn configure_marker_command(fixture: &mut Fixture, marker: &Path) {
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let powershell = PathBuf::from(system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        assert!(
            powershell.is_file(),
            "controlled test executable must exist"
        );
        let escaped_marker = marker.to_string_lossy().replace('\'', "''");
        fixture.command.executable = powershell.display().to_string();
        fixture.command.argv = vec![
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            format!("Add-Content -LiteralPath '{escaped_marker}' -Value 'run'; Write-Output 'ok'"),
        ];
        // The replay test exercises durable receipts, not PowerShell startup latency.
        fixture.command.timeout_seconds = 60;
        fixture.command.inherited_environment = vec!["SystemRoot".to_owned()];
        fixture.command.environment_overrides.clear();
        fixture.material.acceptance_contract.required_commands = vec![fixture.command.clone()];
    }

    fn request_from<'a>(
        material: &'a FrozenRepositoryMaterialV1,
        command: &'a RepositoryAcceptanceCommandV1,
        lineage: &LineageBinding,
        input_artifact_ids: &'a [String],
    ) -> RepositoryCommandExecutionRequest<'a> {
        RepositoryCommandExecutionRequest {
            material,
            command,
            lineage: lineage.clone(),
            workspace_root: Path::new(&material.repository_root),
            workspace_ref: "workspace:task-1",
            source_binding_ref: "repository-test://task-1",
            input_artifact_ids,
        }
    }

    fn reference(id: &str, byte: u8) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: format!("{byte:02x}").repeat(32),
        }
    }

    fn fake(
        result: Result<GovernedProcessReceipt, RepositoryCommandSupervisionFailure>,
    ) -> (FakeExecutor, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            FakeExecutor {
                calls: Arc::clone(&calls),
                result,
            },
            calls,
        )
    }

    #[test]
    fn sealed_read_decoder_round_trips_existing_codec_and_rejects_wrong_bindings() {
        let fixture = Fixture::new("sealed-read-codec");
        let prepared = fixture.prepared();
        let receipt_bytes = encode_receipt(
            &prepared,
            10,
            14,
            &ProcessOutcome {
                exit_code: Some(0),
                failure: None,
                stdout: b"passed".to_vec(),
                stderr: b"note".to_vec(),
                duration_ms: 4,
                output_available: true,
            },
        )
        .expect("existing receipt codec");
        let decoded = decode_repository_command_evidence(RepositoryCommandEvidenceDecodeRequest {
            material: &fixture.material,
            command: &fixture.command,
            lineage: &fixture.lineage,
            workspace_ref: "workspace:task-1",
            source_binding_ref: "repository-test://task-1",
            expected_input_artifact_ids: &fixture.input_artifact_ids,
            observed_intent_input_artifact_ids: &prepared.intent_input_artifact_ids,
            observed_receipt_input_artifact_ids: &prepared.receipt_input_artifact_ids,
            intent_bytes: &prepared.intent_bytes,
            receipt_bytes: &receipt_bytes,
        })
        .expect("sealed decoder");
        assert_eq!(decoded.intent_artifact_id, prepared.intent_artifact_id);
        assert_eq!(decoded.receipt_artifact_id, prepared.receipt_artifact_id);
        assert_eq!(decoded.receipt.exit_code, Some(0));
        assert_eq!(decoded.receipt.stdout, b"passed");
        assert_eq!(decoded.receipt.stderr, b"note");

        let mut wrong_command = fixture.command.clone();
        wrong_command.expected_exit_code = 1;
        assert!(
            decode_repository_command_evidence(RepositoryCommandEvidenceDecodeRequest {
                material: &fixture.material,
                command: &wrong_command,
                lineage: &fixture.lineage,
                workspace_ref: "workspace:task-1",
                source_binding_ref: "repository-test://task-1",
                expected_input_artifact_ids: &fixture.input_artifact_ids,
                observed_intent_input_artifact_ids: &prepared.intent_input_artifact_ids,
                observed_receipt_input_artifact_ids: &prepared.receipt_input_artifact_ids,
                intent_bytes: &prepared.intent_bytes,
                receipt_bytes: &receipt_bytes,
            })
            .is_err()
        );

        let mut wrong_lineage = fixture.lineage.clone();
        wrong_lineage.attempt_revision += 1;
        assert!(
            decode_repository_command_evidence(RepositoryCommandEvidenceDecodeRequest {
                material: &fixture.material,
                command: &fixture.command,
                lineage: &wrong_lineage,
                workspace_ref: "workspace:task-1",
                source_binding_ref: "repository-test://task-1",
                expected_input_artifact_ids: &fixture.input_artifact_ids,
                observed_intent_input_artifact_ids: &prepared.intent_input_artifact_ids,
                observed_receipt_input_artifact_ids: &prepared.receipt_input_artifact_ids,
                intent_bytes: &prepared.intent_bytes,
                receipt_bytes: &receipt_bytes,
            })
            .is_err()
        );

        let wrong_inputs = vec!["artifact:other".to_owned()];
        assert!(
            decode_repository_command_evidence(RepositoryCommandEvidenceDecodeRequest {
                material: &fixture.material,
                command: &fixture.command,
                lineage: &fixture.lineage,
                workspace_ref: "workspace:task-1",
                source_binding_ref: "repository-test://task-1",
                expected_input_artifact_ids: &wrong_inputs,
                observed_intent_input_artifact_ids: &prepared.intent_input_artifact_ids,
                observed_receipt_input_artifact_ids: &prepared.receipt_input_artifact_ids,
                intent_bytes: &prepared.intent_bytes,
                receipt_bytes: &receipt_bytes,
            })
            .is_err()
        );
    }

    fn unmap_process_error(error: RepositoryCommandSupervisionFailure) -> GovernedProcessError {
        match error {
            RepositoryCommandSupervisionFailure::InvalidSpecification => {
                GovernedProcessError::InvalidSpecification
            }
            RepositoryCommandSupervisionFailure::Spawn => GovernedProcessError::Spawn,
            RepositoryCommandSupervisionFailure::InputDelivery => {
                GovernedProcessError::InputDelivery
            }
            RepositoryCommandSupervisionFailure::Timeout => GovernedProcessError::Timeout,
            RepositoryCommandSupervisionFailure::Crashed => GovernedProcessError::Crashed,
            RepositoryCommandSupervisionFailure::OutputLimit => GovernedProcessError::OutputLimit,
            RepositoryCommandSupervisionFailure::Io => GovernedProcessError::Io,
            RepositoryCommandSupervisionFailure::Protocol => GovernedProcessError::Protocol,
        }
    }

    #[tokio::test]
    async fn fresh_intent_is_sealed_before_one_execution_and_receipt_is_sealed() {
        let fixture = Fixture::new("fresh");
        let (executor, calls) = fake(Ok(GovernedProcessReceipt {
            stdout: b"tests passed".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            duration_ms: 12,
        }));
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            executor,
        )
        .expect("runner");
        let outcome = runner.execute(fixture.request()).await.expect("execute");
        let RepositoryCommandExecutionOutcome::Completed(receipt) = outcome else {
            panic!("fresh command must complete");
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipt.exit_code, Some(0));
        let prepared = fixture.prepared();
        let authority = fixture.authority.lock().expect("Authority lock");
        assert_eq!(
            authority
                .read_artifact(&prepared.intent_artifact_id)
                .expect("intent read")
                .expect("intent")
                .status,
            ArtifactStatus::Sealed as i32
        );
        assert_eq!(
            authority
                .read_artifact(&prepared.receipt_artifact_id)
                .expect("receipt read")
                .expect("receipt")
                .status,
            ArtifactStatus::Sealed as i32
        );
    }

    #[tokio::test]
    async fn exact_replay_on_same_helper_does_not_spawn_or_grow_store() {
        let fixture = Fixture::new("same-helper-replay");
        let (executor, calls) = fake(Ok(GovernedProcessReceipt {
            stdout: b"stable".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            duration_ms: 1,
        }));
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            executor,
        )
        .expect("runner");
        runner.execute(fixture.request()).await.expect("first");
        let counts = fixture
            .authority
            .lock()
            .expect("Authority lock")
            .inspect_store()
            .expect("counts");
        let replay = runner.execute(fixture.request()).await.expect("replay");
        assert!(matches!(
            replay,
            RepositoryCommandExecutionOutcome::Replayed(_)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture
                .authority
                .lock()
                .expect("Authority lock")
                .inspect_store()
                .expect("replay counts"),
            counts
        );
    }

    #[tokio::test]
    async fn concurrent_same_helper_calls_execute_once_and_second_replays() {
        let fixture = Fixture::new("concurrent-same-helper");
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            GateExecutor {
                calls: Arc::clone(&calls),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        )
        .expect("runner");

        let first = runner.execute(fixture.request());
        let second_after_first_enters = async {
            entered.notified().await;
            let second = runner.execute(fixture.request());
            release.notify_one();
            second.await
        };
        let (first, second) = tokio::join!(first, second_after_first_enters);
        assert!(matches!(
            first.expect("first call"),
            RepositoryCommandExecutionOutcome::Completed(_)
        ));
        assert!(matches!(
            second.expect("second call"),
            RepositoryCommandExecutionOutcome::Replayed(_)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn sqlcipher_reopen_replays_sealed_receipt_without_running_real_process_again() {
        let label = "disk-receipt-replay";
        let mut fixture = Fixture::new(label);
        let marker = fixture.root.path().join("command-runs.txt");
        configure_marker_command(&mut fixture, &marker);
        let runner = RepositoryCommandArtifactRunner::new(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
        )
        .expect("runner");
        let first = runner.execute(fixture.request()).await.expect("first run");
        let RepositoryCommandExecutionOutcome::Completed(first) = first else {
            panic!("fresh process must execute before replay");
        };
        assert_eq!(
            first.supervision_failure, None,
            "process supervision must succeed"
        );
        assert_eq!(
            first.exit_code,
            Some(0),
            "marker process must exit successfully"
        );
        assert_eq!(
            std::fs::read_to_string(&marker)
                .expect("execution marker")
                .lines()
                .collect::<Vec<_>>(),
            vec!["run"]
        );
        let counts = fixture
            .authority
            .lock()
            .expect("Authority lock")
            .inspect_store()
            .expect("store counts");

        drop(runner);
        let Fixture {
            root,
            authority,
            material,
            command,
            config,
            lineage,
            input_artifact_ids,
        } = fixture;
        drop(authority);
        let reopened_authority = open_fixture_authority(root.path(), label);
        let restarted =
            RepositoryCommandArtifactRunner::new(Arc::clone(&reopened_authority), config)
                .expect("restarted runner");
        let replay = restarted
            .execute(request_from(
                &material,
                &command,
                &lineage,
                &input_artifact_ids,
            ))
            .await
            .expect("replay after reopen");
        assert!(matches!(
            replay,
            RepositoryCommandExecutionOutcome::Replayed(_)
        ));
        assert_eq!(
            std::fs::read_to_string(&marker)
                .expect("unchanged execution marker")
                .lines()
                .collect::<Vec<_>>(),
            vec!["run"]
        );
        assert_eq!(
            reopened_authority
                .lock()
                .expect("Authority lock")
                .inspect_store()
                .expect("reopened store counts"),
            counts
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn sqlcipher_reopen_with_intent_only_blocks_without_running_real_process() {
        let label = "disk-intent-only";
        let mut fixture = Fixture::new(label);
        let marker = fixture.root.path().join("command-runs.txt");
        configure_marker_command(&mut fixture, &marker);
        let prepared = fixture.prepared();
        {
            let mut authority = fixture.authority.lock().expect("Authority lock");
            assert!(matches!(
                inspect_or_persist_intent(&mut authority, &fixture.config, &prepared)
                    .expect("persist sealed intent"),
                IntentPreflight::Fresh
            ));
        }

        let Fixture {
            root,
            authority,
            material,
            command,
            config,
            lineage,
            input_artifact_ids,
        } = fixture;
        drop(authority);
        let reopened_authority = open_fixture_authority(root.path(), label);
        let restarted = RepositoryCommandArtifactRunner::new(reopened_authority, config)
            .expect("restarted runner");
        let outcome = restarted
            .execute(request_from(
                &material,
                &command,
                &lineage,
                &input_artifact_ids,
            ))
            .await
            .expect("intent-only recovery");
        let RepositoryCommandExecutionOutcome::Blocked(blocked) = outcome else {
            panic!("intent-only recovery must block");
        };
        assert_eq!(
            blocked.reason,
            RepositoryCommandBlockedReason::ExistingIntentWithoutReceipt
        );
        assert_eq!(blocked.lineage, lineage);
        assert!(!marker.exists(), "recovery must not start the command");
    }

    #[tokio::test]
    async fn new_helper_with_intent_only_returns_exact_blocked_without_spawn() {
        let fixture = Fixture::new("intent-only");
        let prepared = fixture.prepared();
        {
            let mut authority = fixture.authority.lock().expect("Authority lock");
            assert!(matches!(
                inspect_or_persist_intent(&mut authority, &fixture.config, &prepared)
                    .expect("persist intent"),
                IntentPreflight::Fresh
            ));
        }
        let (executor, calls) = fake(Ok(GovernedProcessReceipt {
            stdout: b"must not run".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            duration_ms: 1,
        }));
        let restarted = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            executor,
        )
        .expect("restarted helper");
        let outcome = restarted.execute(fixture.request()).await.expect("recover");
        let RepositoryCommandExecutionOutcome::Blocked(blocked) = outcome else {
            panic!("intent-only recovery must block");
        };
        assert_eq!(
            blocked.reason,
            RepositoryCommandBlockedReason::ExistingIntentWithoutReceipt
        );
        assert_eq!(blocked.lineage, fixture.lineage);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sealed_receipt_replays_real_nonzero_stdout_and_stderr_without_spawn() {
        let fixture = Fixture::new("nonzero-replay");
        let (executor, calls) = fake(Ok(GovernedProcessReceipt {
            stdout: b"criterion failed".to_vec(),
            stderr: b"expected 3 got 2".to_vec(),
            exit_code: 7,
            duration_ms: 9,
        }));
        let first = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            executor,
        )
        .expect("first helper");
        first.execute(fixture.request()).await.expect("first run");
        let (never, replay_calls) = fake(Err(RepositoryCommandSupervisionFailure::Spawn));
        let restarted = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            never,
        )
        .expect("restarted helper");
        let outcome = restarted.execute(fixture.request()).await.expect("replay");
        let RepositoryCommandExecutionOutcome::Replayed(receipt) = outcome else {
            panic!("sealed receipt must replay");
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
        assert_eq!(receipt.exit_code, Some(7));
        assert_eq!(receipt.stdout, b"criterion failed");
        assert_eq!(receipt.stderr, b"expected 3 got 2");
    }

    #[tokio::test]
    async fn supervision_failure_receipt_has_null_exit_and_unavailable_output() {
        let fixture = Fixture::new("failure");
        let (executor, calls) = fake(Err(RepositoryCommandSupervisionFailure::Timeout));
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            executor,
        )
        .expect("runner");
        let outcome = runner.execute(fixture.request()).await.expect("execute");
        let RepositoryCommandExecutionOutcome::Completed(receipt) = outcome else {
            panic!("known supervision failure must be receipted");
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipt.exit_code, None);
        assert_eq!(
            receipt.supervision_failure,
            Some(RepositoryCommandSupervisionFailure::Timeout)
        );
        assert!(receipt.stdout.is_empty());
        assert!(receipt.stderr.is_empty());
    }

    #[test]
    fn staged_receipt_is_sealed_from_verified_persisted_bytes_without_execution() {
        let fixture = Fixture::new("staged-receipt");
        let prepared = fixture.prepared();
        let outcome = ProcessOutcome {
            exit_code: Some(7),
            failure: None,
            stdout: b"failed".to_vec(),
            stderr: b"details".to_vec(),
            duration_ms: 4,
            output_available: true,
        };
        let bytes = encode_receipt(&prepared, 10, 14, &outcome).expect("receipt bytes");
        {
            let mut authority = fixture.authority.lock().expect("Authority lock");
            assert!(matches!(
                inspect_or_persist_intent(&mut authority, &fixture.config, &prepared)
                    .expect("intent"),
                IntentPreflight::Fresh
            ));
            let address = content_address(&bytes);
            authority.put_blob(&bytes, &address).expect("receipt blob");
            let staged = authority
                .execute(
                    &stage_command(
                        &prepared,
                        artifact_descriptor(
                            &prepared,
                            &fixture.config,
                            ArtifactKind::Receipt,
                            address,
                        ),
                        "stage-receipt",
                    ),
                    &principal(
                        ArtifactPrincipalKind::SupervisedRunner,
                        &fixture.config.supervised_runner_principal_id,
                    ),
                )
                .expect("stage receipt");
            assert!(staged.committed);
            let recovered = inspect_or_persist_intent(&mut authority, &fixture.config, &prepared)
                .expect("recover staged receipt");
            let IntentPreflight::Replay(receipt) = recovered else {
                panic!("staged receipt must recover as replay");
            };
            assert_eq!(receipt.exit_code, Some(7));
            assert_eq!(receipt.stdout, b"failed");
            assert_eq!(
                authority
                    .read_artifact(&prepared.receipt_artifact_id)
                    .expect("read receipt")
                    .expect("receipt")
                    .status,
                ArtifactStatus::Sealed as i32
            );
        }
    }

    #[test]
    fn receipt_with_wall_clock_rollback_keeps_monotonic_duration_and_output() {
        let fixture = Fixture::new("wall-clock-rollback");
        let prepared = fixture.prepared();
        let outcome = ProcessOutcome {
            exit_code: Some(0),
            failure: None,
            stdout: b"completed".to_vec(),
            stderr: Vec::new(),
            duration_ms: 37,
            output_available: true,
        };
        let bytes = encode_receipt(&prepared, 20, 10, &outcome).expect("receipt bytes");
        let decoded = decode_receipt(&prepared, &bytes).expect("clock rollback is valid");
        assert_eq!(decoded.duration_ms, 37);
        assert_eq!(decoded.stdout, b"completed");
    }

    #[tokio::test]
    async fn different_tasks_and_commands_use_distinct_artifacts_and_both_execute() {
        let mut fixture = Fixture::new("distinct-commands");
        let (executor, first_calls) = fake(Ok(GovernedProcessReceipt {
            stdout: b"done".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            duration_ms: 1,
        }));
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            executor,
        )
        .expect("runner");
        runner.execute(fixture.request()).await.expect("first");

        let mut second_command = fixture.command.clone();
        second_command.command_id = "tests-2".to_owned();
        second_command.criterion_id = "lint".to_owned();
        second_command.argv = vec!["--second-safe-fixture".to_owned()];
        fixture
            .material
            .acceptance_contract
            .required_commands
            .push(second_command.clone());
        let mut second_lineage = fixture.lineage.clone();
        second_lineage.task_id = "task-2".to_owned();
        second_lineage.run_id = "run-2".to_owned();
        second_lineage.step_id = "step-2".to_owned();
        second_lineage.attempt_id = "attempt-2".to_owned();
        second_lineage.dispatch_id = "dispatch-2".to_owned();
        let second_inputs = vec!["artifact:baseline:dispatch-2".to_owned()];
        let first_prepared = fixture.prepared();
        let second_request = RepositoryCommandExecutionRequest {
            material: &fixture.material,
            command: &second_command,
            lineage: second_lineage,
            workspace_root: Path::new(&fixture.material.repository_root),
            workspace_ref: "workspace:task-2",
            source_binding_ref: "repository-test://task-2",
            input_artifact_ids: &second_inputs,
        };
        let second_prepared =
            PreparedCommand::new(&fixture.config, second_request).expect("second prepared command");
        let (second_executor, second_calls) = fake(Ok(GovernedProcessReceipt {
            stdout: b"second done".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            duration_ms: 1,
        }));
        let second = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&fixture.authority),
            fixture.config.clone(),
            second_executor,
        )
        .expect("second runner");
        let outcome = second
            .execute(RepositoryCommandExecutionRequest {
                material: &fixture.material,
                command: &second_command,
                lineage: second_prepared.lineage.clone(),
                workspace_root: Path::new(&fixture.material.repository_root),
                workspace_ref: "workspace:task-2",
                source_binding_ref: "repository-test://task-2",
                input_artifact_ids: &second_inputs,
            })
            .await
            .expect("second command");
        assert!(matches!(
            outcome,
            RepositoryCommandExecutionOutcome::Completed(_)
        ));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
        assert_ne!(
            first_prepared.intent_artifact_id,
            second_prepared.intent_artifact_id
        );
        assert_ne!(
            first_prepared.receipt_artifact_id,
            second_prepared.receipt_artifact_id
        );
    }
}
