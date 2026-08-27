#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use egopulse_client_operations::{ClientReadError, attach};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    harness::v1::{ApprovalDecision, ApprovalRequestLifecycleKind},
    localapi::v1::{
        AvailableActionKind, ClientSurface, DecideHarnessApprovalRequest,
        ExecuteMemoryMutationRequest, ExecuteTaskCommandRequest, LocalApiError,
        MemoryMutationCommand, MemoryMutationReceipt, RetrieveMemoryRequest,
        memory_mutation_command, retrieve_memory_response,
    },
    policy::v1::{
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, policy_decision_command,
    },
    task::v1::{
        CreateTaskCommand, RequestTaskCancellationCommand, TaskCommand, TaskStatus, task_command,
        task_command_result,
    },
};
use egopulse_local_api::{LocalApiClient, LocalTransport};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundationStatus {
    product: &'static str,
    architecture_version: &'static str,
    status: &'static str,
    transport: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTask {
    task_id: String,
    revision: u64,
    work_revision: u64,
    status: String,
    work_type: String,
    hold_reason_code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopApproval {
    approval_request_id: String,
    task_id: String,
    request_lifecycle: String,
    request_revision: u64,
    display_summary_ref: String,
    requested_scope_ref: String,
    action_digest_sha256: String,
    request_observation_id: String,
    request_observation_sequence: u64,
    available_action_codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopSnapshot {
    instance: String,
    projection_health: String,
    stale: bool,
    position: String,
    tasks: Vec<DesktopTask>,
    approvals: Vec<DesktopApproval>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTaskCreateResult {
    task_id: String,
    revision: u64,
    status: String,
    replayed: bool,
    await_token_present: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTaskCancellationRequest {
    instance: String,
    task_id: String,
    expected_revision: u64,
    reason_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTaskCreateRequest {
    instance: String,
    work_type: String,
    input_snapshot_id: String,
    target_scope_ref: String,
    acceptance_contract_id: String,
    acceptance_contract_version: String,
    acceptance_contract_sha256: String,
    budget_profile_id: String,
    budget_profile_version: String,
    budget_profile_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopApprovalDecisionRequest {
    instance: String,
    approval_request_id: String,
    expected_action_digest_sha256: String,
    expected_request_observation_id: String,
    expected_request_observation_sequence: u64,
    expected_request_revision: u64,
    decision: String,
    reason_code: String,
    confirmation_proof_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopApprovalDecisionResult {
    authority_decision_ref: String,
    committed: bool,
    replayed: bool,
    decision: String,
    state: String,
    state_revision: u64,
    await_token_present: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopMemoryCandidateRequest {
    instance: String,
    memory_id: String,
    content: String,
    source_ref: String,
    scope_ref: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopMemoryReviewRequest {
    instance: String,
    memory_id: String,
    expected_revision: u64,
    evidence_ref: String,
    idempotency_key: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopMemoryMutationResult {
    memory_id: String,
    revision: u64,
    state: String,
    event_id: String,
    request_digest_sha256: String,
    acknowledged_after_durability_barrier: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopMemoryRetrievalCandidate {
    memory_id: String,
    source_ref: String,
    content_sha256: String,
    score: f64,
    matched_terms: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopMemoryRetrievalResult {
    algorithm_id: String,
    query_sha256: String,
    snapshot_sha256: String,
    evidence_ref: String,
    candidates: Vec<DesktopMemoryRetrievalCandidate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopMemoryRetrievalRequest {
    instance: String,
    query: String,
    scope_ref: String,
    max_results: u32,
    min_score: f64,
}

fn transport_name(transport: LocalTransport) -> &'static str {
    match transport {
        LocalTransport::WindowsNamedPipe => "windows-named-pipe",
        LocalTransport::UnixDomainSocket => "unix-domain-socket",
    }
}

fn safe_local_api_error(error: &LocalApiError) -> String {
    format!(
        "local API rejected the command: code={} retryable={} required_action={}",
        error.code,
        error.retryable,
        error.required_action_code.as_deref().unwrap_or("none")
    )
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

#[tauri::command]
fn foundation_status() -> FoundationStatus {
    let client = LocalApiClient::platform_default();
    let health = client.foundation_health();
    FoundationStatus {
        product: "EgoPulse",
        architecture_version: health.architecture_version,
        status: health.state.as_str(),
        transport: transport_name(client.transport()),
    }
}

#[tauri::command]
async fn dashboard_snapshot(instance: String) -> Result<DesktopSnapshot, String> {
    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", uuid::Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    let projection = attachment
        .read_projection_snapshot()
        .await
        .map_err(|error| match error {
            ClientReadError::Api(error) => format!("local API rejected the read: {error:?}"),
            other => other.to_string(),
        })?;
    let position = projection
        .metadata
        .position
        .as_ref()
        .map(|value| format!("{}:{}", value.epoch, value.sequence))
        .unwrap_or_else(|| "unknown".to_owned());
    let projection_health =
        egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionHealth::try_from(
            projection.metadata.health,
        )
        .map(|value| value.as_str_name().to_owned())
        .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned());
    let tasks = projection
        .tasks
        .into_iter()
        .filter_map(|view| view.task)
        .map(|task| DesktopTask {
            task_id: task.task_id,
            revision: task.revision,
            work_revision: task.work_revision,
            status: TaskStatus::try_from(task.status)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "TASK_STATUS_UNKNOWN".to_owned()),
            work_type: task.work_type,
            hold_reason_code: task.hold_reason_code,
        })
        .collect();
    let approvals = projection
        .approvals
        .into_iter()
        .map(|approval| DesktopApproval {
            approval_request_id: approval.approval_request_id,
            task_id: approval.task_id,
            request_lifecycle: ApprovalRequestLifecycleKind::try_from(approval.request_lifecycle)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "APPROVAL_REQUEST_LIFECYCLE_UNKNOWN".to_owned()),
            request_revision: approval.request_revision,
            display_summary_ref: approval.display_summary_ref,
            requested_scope_ref: approval.requested_scope_ref,
            action_digest_sha256: approval.action_digest_sha256,
            request_observation_id: approval.request_observation_id,
            request_observation_sequence: approval.request_observation_sequence,
            available_action_codes: approval
                .available_actions
                .into_iter()
                .filter_map(|action| AvailableActionKind::try_from(action.kind).ok())
                .map(|action| action.as_str_name().to_owned())
                .collect(),
        })
        .collect();
    Ok(DesktopSnapshot {
        instance,
        projection_health,
        stale: projection.metadata.stale,
        position,
        tasks,
        approvals,
    })
}

fn parse_approval_decision(value: &str) -> Result<i32, String> {
    match value {
        "allow-once" => Ok(ApprovalDecision::AllowOnce as i32),
        "deny" => Ok(ApprovalDecision::Deny as i32),
        "cancel-attempt" => Ok(ApprovalDecision::CancelAttempt as i32),
        _ => Err("decision must be allow-once, deny, or cancel-attempt".to_owned()),
    }
}

#[tauri::command]
async fn decide_approval(
    request: DesktopApprovalDecisionRequest,
) -> Result<DesktopApprovalDecisionResult, String> {
    let DesktopApprovalDecisionRequest {
        instance,
        approval_request_id,
        expected_action_digest_sha256,
        expected_request_observation_id,
        expected_request_observation_sequence,
        expected_request_revision,
        decision,
        reason_code,
        confirmation_proof_ref,
    } = request;
    require_non_empty(&approval_request_id, "approval_request_id")?;
    require_non_empty(
        &expected_action_digest_sha256,
        "expected_action_digest_sha256",
    )?;
    require_non_empty(
        &expected_request_observation_id,
        "expected_request_observation_id",
    )?;
    require_non_empty(&reason_code, "reason_code")?;
    let decision = parse_approval_decision(&decision)?;
    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    attachment
        .require_command(
            "LocalCommandGatewayService/DecideHarnessApproval",
            "issue_harness_approval_decision",
        )
        .map_err(|error| error.to_string())?;

    let correlation_id = Uuid::now_v7().to_string();
    let mut command = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::IssueHarnessApprovalDecision(
                IssueHarnessApprovalDecisionCommand {
                    metadata: Some(egopulse_client_operations::command_metadata(
                        &correlation_id,
                        "egopulse-desktop/approval-decide",
                    )),
                    approval_request_id,
                    expected_action_digest_sha256,
                    expected_request_observation_id,
                    expected_request_observation_sequence,
                    decision,
                    reason_code,
                    confirmation_proof_ref,
                    expected_request_revision,
                },
            ),
        ),
    };
    egopulse_client_operations::set_policy_digest(&mut command);
    let issue = match command.command {
        Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) => issue,
        _ => unreachable!("Desktop always constructs issue approval decision"),
    };
    let response = attachment
        .connection
        .command_gateway_service()
        .decide_harness_approval(DecideHarnessApprovalRequest {
            client: Some(
                attachment
                    .metadata(Some(correlation_id))
                    .map_err(|error| error.to_string())?,
            ),
            command: Some(issue),
        })
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
    if let Some(error) = response.gateway_error.as_ref() {
        return Err(safe_local_api_error(error));
    }
    let result = response
        .sanitized_authority_result
        .ok_or_else(|| "sanitized approval result missing".to_owned())?;
    if result.error_code != 0 {
        return Err(format!(
            "approval authority rejected the command: code={} fingerprint={}",
            result.error_code,
            result.safe_error_fingerprint.as_deref().unwrap_or("none")
        ));
    }
    Ok(DesktopApprovalDecisionResult {
        authority_decision_ref: result.authority_decision_ref,
        committed: result.committed,
        replayed: result.replayed,
        decision: ApprovalDecision::try_from(result.decision)
            .map(|value| value.as_str_name().to_owned())
            .unwrap_or_else(|_| "APPROVAL_DECISION_UNKNOWN".to_owned()),
        state: egopulse_domain_contracts::v01::egopulse::policy::v1::HarnessApprovalDecisionStateKind::try_from(result.state)
            .map(|value| value.as_str_name().to_owned())
            .unwrap_or_else(|_| "HARNESS_APPROVAL_DECISION_STATE_KIND_UNKNOWN".to_owned()),
        state_revision: result.state_revision,
        await_token_present: response.await_token.is_some(),
    })
}

async fn execute_memory_mutation(
    instance: String,
    mut branch: memory_mutation_command::Command,
    oneof: &'static str,
) -> Result<DesktopMemoryMutationResult, String> {
    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    attachment
        .require_command("LocalCommandGatewayService/ExecuteMemoryMutation", oneof)
        .map_err(|error| error.to_string())?;
    let correlation_id = Uuid::now_v7().to_string();
    let metadata = attachment
        .metadata(Some(correlation_id))
        .map_err(|error| error.to_string())?;
    match &mut branch {
        memory_mutation_command::Command::SubmitMemoryCandidate(command) => {
            command.metadata = Some(metadata.clone())
        }
        memory_mutation_command::Command::AcceptMemory(command) => {
            command.metadata = Some(metadata.clone())
        }
        memory_mutation_command::Command::RevokeMemory(command) => {
            command.metadata = Some(metadata.clone())
        }
    }
    let response = attachment
        .connection
        .command_gateway_service()
        .execute_memory_mutation(ExecuteMemoryMutationRequest {
            client: Some(metadata),
            command: Some(MemoryMutationCommand {
                command: Some(branch),
            }),
        })
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
    if let Some(error) = response.gateway_error.as_ref() {
        return Err(safe_local_api_error(error));
    }
    let receipt: MemoryMutationReceipt = response
        .authority_result
        .ok_or_else(|| "memory mutation receipt missing".to_owned())?;
    Ok(DesktopMemoryMutationResult {
        memory_id: receipt.memory_id,
        revision: receipt.revision,
        state: receipt.state,
        event_id: receipt.event_id,
        request_digest_sha256: receipt.request_digest_sha256,
        acknowledged_after_durability_barrier: receipt.acknowledged_after_durability_barrier,
    })
}

#[tauri::command]
async fn submit_memory_candidate(
    request: DesktopMemoryCandidateRequest,
) -> Result<DesktopMemoryMutationResult, String> {
    let DesktopMemoryCandidateRequest {
        instance,
        memory_id,
        content,
        source_ref,
        scope_ref,
        idempotency_key,
    } = request;
    require_non_empty(&memory_id, "memory_id")?;
    require_non_empty(&content, "content")?;
    require_non_empty(&source_ref, "source_ref")?;
    require_non_empty(&scope_ref, "scope_ref")?;
    require_non_empty(&idempotency_key, "idempotency_key")?;
    execute_memory_mutation(
        instance,
        memory_mutation_command::Command::SubmitMemoryCandidate(
            egopulse_domain_contracts::v01::egopulse::localapi::v1::SubmitMemoryCandidateCommand {
                metadata: None,
                memory_id,
                content,
                source_ref,
                scope_ref,
                idempotency_key,
            },
        ),
        "submit_memory_candidate",
    )
    .await
}

#[tauri::command]
async fn accept_memory(
    request: DesktopMemoryReviewRequest,
) -> Result<DesktopMemoryMutationResult, String> {
    let DesktopMemoryReviewRequest {
        instance,
        memory_id,
        expected_revision,
        evidence_ref,
        idempotency_key,
    } = request;
    require_non_empty(&memory_id, "memory_id")?;
    require_non_empty(&evidence_ref, "evidence_ref")?;
    require_non_empty(&idempotency_key, "idempotency_key")?;
    execute_memory_mutation(
        instance,
        memory_mutation_command::Command::AcceptMemory(
            egopulse_domain_contracts::v01::egopulse::localapi::v1::AcceptMemoryCommand {
                metadata: None,
                memory_id,
                expected_revision,
                evidence_ref,
                idempotency_key,
            },
        ),
        "accept_memory",
    )
    .await
}

#[tauri::command]
async fn revoke_memory(
    request: DesktopMemoryReviewRequest,
) -> Result<DesktopMemoryMutationResult, String> {
    let DesktopMemoryReviewRequest {
        instance,
        memory_id,
        expected_revision,
        evidence_ref,
        idempotency_key,
    } = request;
    require_non_empty(&memory_id, "memory_id")?;
    require_non_empty(&evidence_ref, "evidence_ref")?;
    require_non_empty(&idempotency_key, "idempotency_key")?;
    execute_memory_mutation(
        instance,
        memory_mutation_command::Command::RevokeMemory(
            egopulse_domain_contracts::v01::egopulse::localapi::v1::RevokeMemoryCommand {
                metadata: None,
                memory_id,
                expected_revision,
                evidence_ref,
                idempotency_key,
            },
        ),
        "revoke_memory",
    )
    .await
}

#[tauri::command]
async fn retrieve_memory(
    request: DesktopMemoryRetrievalRequest,
) -> Result<DesktopMemoryRetrievalResult, String> {
    let DesktopMemoryRetrievalRequest {
        instance,
        query,
        scope_ref,
        max_results,
        min_score,
    } = request;
    require_non_empty(&query, "query")?;
    require_non_empty(&scope_ref, "scope_ref")?;
    if max_results == 0 {
        return Err("max_results must be positive".to_owned());
    }
    if !(0.0..=1.0).contains(&min_score) {
        return Err("min_score must be between 0 and 1".to_owned());
    }
    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    attachment
        .require_rpc("LocalCognitionService/RetrieveMemory")
        .map_err(|error| error.to_string())?;
    let response = attachment
        .connection
        .cognition_service()
        .retrieve_memory(RetrieveMemoryRequest {
            client: Some(
                attachment
                    .metadata(None)
                    .map_err(|error| error.to_string())?,
            ),
            query,
            scope_ref,
            max_results,
            min_score,
        })
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
    let result = match response.outcome {
        Some(retrieve_memory_response::Outcome::Result(result)) => result,
        Some(retrieve_memory_response::Outcome::Error(error)) => {
            return Err(safe_local_api_error(&error));
        }
        None => return Err("memory retrieval outcome missing".to_owned()),
    };
    Ok(DesktopMemoryRetrievalResult {
        algorithm_id: result.algorithm_id,
        query_sha256: result.query_sha256,
        snapshot_sha256: result.snapshot_sha256,
        evidence_ref: result.evidence_ref,
        candidates: result
            .candidates
            .into_iter()
            .map(|candidate| DesktopMemoryRetrievalCandidate {
                memory_id: candidate.memory_id,
                source_ref: candidate.source_ref,
                content_sha256: candidate.content_sha256,
                score: candidate.score,
                matched_terms: candidate.matched_terms,
            })
            .collect(),
    })
}

#[tauri::command]
async fn create_task(request: DesktopTaskCreateRequest) -> Result<DesktopTaskCreateResult, String> {
    let DesktopTaskCreateRequest {
        instance,
        work_type,
        input_snapshot_id,
        target_scope_ref,
        acceptance_contract_id,
        acceptance_contract_version,
        acceptance_contract_sha256,
        budget_profile_id,
        budget_profile_version,
        budget_profile_sha256,
    } = request;
    require_non_empty(&work_type, "work_type")?;
    require_non_empty(&input_snapshot_id, "input_snapshot_id")?;
    require_non_empty(&target_scope_ref, "target_scope_ref")?;
    require_non_empty(&acceptance_contract_id, "acceptance_contract_id")?;
    require_non_empty(&acceptance_contract_version, "acceptance_contract_version")?;
    require_non_empty(&acceptance_contract_sha256, "acceptance_contract_sha256")?;
    require_non_empty(&budget_profile_id, "budget_profile_id")?;
    require_non_empty(&budget_profile_version, "budget_profile_version")?;
    require_non_empty(&budget_profile_sha256, "budget_profile_sha256")?;

    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    attachment
        .require_command(
            "LocalCommandGatewayService/ExecuteTaskCommand",
            "create_task",
        )
        .map_err(|error| error.to_string())?;

    let correlation_id = Uuid::now_v7().to_string();
    let mut command = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(egopulse_client_operations::command_metadata(
                &correlation_id,
                "egopulse-desktop/task-create",
            )),
            work_type,
            input_snapshot_id,
            target_scope_ref,
            acceptance_contract_ref: Some(ContractReference {
                contract_id: acceptance_contract_id,
                version: acceptance_contract_version,
                sha256: acceptance_contract_sha256,
            }),
            budget_profile_ref: Some(ContractReference {
                contract_id: budget_profile_id,
                version: budget_profile_version,
                sha256: budget_profile_sha256,
            }),
        })),
    };
    egopulse_client_operations::set_task_digest(&mut command);
    let response = attachment
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(
                attachment
                    .metadata(Some(correlation_id))
                    .map_err(|error| error.to_string())?,
            ),
            command: Some(command),
        })
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
    if let Some(error) = response.gateway_error.as_ref() {
        return Err(safe_local_api_error(error));
    }
    let authority_result = response
        .authority_result
        .ok_or_else(|| "task authority result missing".to_owned())?;
    let replayed = authority_result.replayed;
    let task = match authority_result.outcome {
        Some(task_command_result::Outcome::Task(task)) => Ok(task),
        Some(task_command_result::Outcome::Error(error)) => Err(format!(
            "task authority rejected the command: code={} detail={}",
            error.code, error.safe_detail_code
        )),
        None => Err("task authority outcome missing".to_owned()),
    }?;
    Ok(DesktopTaskCreateResult {
        task_id: task.task_id,
        revision: task.revision,
        status: TaskStatus::try_from(task.status)
            .map(|value| value.as_str_name().to_owned())
            .unwrap_or_else(|_| "TASK_STATUS_UNKNOWN".to_owned()),
        replayed,
        await_token_present: response.await_token.is_some(),
    })
}

#[tauri::command]
async fn cancel_task(
    request: DesktopTaskCancellationRequest,
) -> Result<DesktopTaskCreateResult, String> {
    let DesktopTaskCancellationRequest {
        instance,
        task_id,
        expected_revision,
        reason_code,
    } = request;
    require_non_empty(&task_id, "task_id")?;
    require_non_empty(&reason_code, "reason_code")?;
    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    attachment
        .require_command(
            "LocalCommandGatewayService/ExecuteTaskCommand",
            "request_task_cancellation",
        )
        .map_err(|error| error.to_string())?;

    let correlation_id = Uuid::now_v7().to_string();
    let mut command = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(egopulse_client_operations::command_metadata(
                    &correlation_id,
                    "egopulse-desktop/task-cancel",
                )),
                task_id,
                expected_revision,
                reason_code,
            },
        )),
    };
    egopulse_client_operations::set_task_digest(&mut command);
    let response = attachment
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(
                attachment
                    .metadata(Some(correlation_id))
                    .map_err(|error| error.to_string())?,
            ),
            command: Some(command),
        })
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
    if let Some(error) = response.gateway_error.as_ref() {
        return Err(safe_local_api_error(error));
    }
    let authority_result = response
        .authority_result
        .ok_or_else(|| "task authority result missing".to_owned())?;
    let replayed = authority_result.replayed;
    let task = match authority_result.outcome {
        Some(task_command_result::Outcome::Task(task)) => Ok(task),
        Some(task_command_result::Outcome::Error(error)) => Err(format!(
            "task authority rejected the command: code={} detail={}",
            error.code, error.safe_detail_code
        )),
        None => Err("task authority outcome missing".to_owned()),
    }?;
    Ok(DesktopTaskCreateResult {
        task_id: task.task_id,
        revision: task.revision,
        status: TaskStatus::try_from(task.status)
            .map(|value| value.as_str_name().to_owned())
            .unwrap_or_else(|_| "TASK_STATUS_UNKNOWN".to_owned()),
        replayed,
        await_token_present: response.await_token.is_some(),
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            foundation_status,
            dashboard_snapshot,
            create_task,
            cancel_task,
            decide_approval,
            submit_memory_candidate,
            accept_memory,
            revoke_memory,
            retrieve_memory
        ])
        .run(tauri::generate_context!())
        .expect("failed to run EgoPulse desktop foundation shell");
}
