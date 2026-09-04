use super::{
    AuthenticatedCollaborationPrincipal, AuthorityClock, CollaborationControl,
    CollaborationControlError, CollaborationPrincipalKind, CollaborationReferenceGuard,
    DispatchMaterial, HarnessEvidenceResolver, canonical_dispatch_fingerprint, seal_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::{
        AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptCommandBase, CollaborationCommand,
        CollaborationSnapshot, CreateAttemptCommand, CreateRunCommand, RecordDispatchIntentCommand,
        RunCommandBase, RunPlan, collaboration_command, collaboration_command_result,
    },
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::DispatchEnvelope,
    task::v1::TaskSnapshot,
};
use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct SingleHarnessWorkConfig {
    pub run_id: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub plan: RunPlan,
    pub harness_id: String,
    pub capability_profile_ref: ContractReference,
    pub workspace_ref: String,
    pub lease_policy_ref: ContractReference,
    pub owner_instance_id: String,
    pub material: DispatchMaterial,
    pub task_authority_principal_id: String,
    pub collaboration_principal_id: String,
    pub attempt_supervisor_principal_id: String,
    pub harness_adapter_principal_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleHarnessWorkResult {
    pub run_id: String,
    pub step_id: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub envelope: DispatchEnvelope,
}

#[derive(Debug, Error)]
pub enum SingleHarnessWorkError {
    #[error("collaboration control operation failed")]
    Control(#[from] CollaborationControlError),
    #[error("single harness workflow command was rejected: {0}")]
    CommandRejected(String),
    #[error("single harness workflow returned no committed snapshot")]
    MissingSnapshot,
    #[error("single harness workflow did not produce its dispatch envelope")]
    DispatchNotProduced,
    #[error("single harness workflow configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("system clock is before the Unix epoch")]
    Clock,
}

pub fn start_single_harness_workflow<G, C>(
    control: &mut CollaborationControl<G, C>,
    task: &TaskSnapshot,
    config: &SingleHarnessWorkConfig,
) -> Result<SingleHarnessWorkResult, SingleHarnessWorkError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    validate_config(task, config)?;
    let step_id = config.plan.steps[0].step_id.clone();
    let task_principal = principal(
        CollaborationPrincipalKind::TaskAuthority,
        &config.task_authority_principal_id,
    );
    let collaboration_principal = principal(
        CollaborationPrincipalKind::CollaborationControl,
        &config.collaboration_principal_id,
    );
    let supervisor_principal = principal(
        CollaborationPrincipalKind::AttemptSupervisor,
        &config.attempt_supervisor_principal_id,
    );
    let harness_principal = principal(
        CollaborationPrincipalKind::HarnessAdapter,
        &config.harness_adapter_principal_id,
    );

    let run = snapshot_after(control, &create_run_command(task, config)?, &task_principal)?;
    let active = snapshot_after(
        control,
        &activate_run_command(&run, task.revision, config)?,
        &task_principal,
    )?;
    let attempt = snapshot_after(
        control,
        &create_attempt_command(&active, &step_id, config)?,
        &collaboration_principal,
    )?;
    let leased = snapshot_after(
        control,
        &acquire_lease_command(&attempt, &step_id, config)?,
        &supervisor_principal,
    )?;
    let dispatch_command = dispatch_intent_command(&leased, &step_id, config)?;
    snapshot_after(control, &dispatch_command, &collaboration_principal)?;
    let pending = control.pending_dispatches(&harness_principal)?;
    let envelope = pending
        .into_iter()
        .find(|value| value.envelope.dispatch_id == config.dispatch_id)
        .map(|value| value.envelope)
        .ok_or(SingleHarnessWorkError::DispatchNotProduced)?;

    Ok(SingleHarnessWorkResult {
        run_id: config.run_id.clone(),
        step_id,
        attempt_id: config.attempt_id.clone(),
        dispatch_id: config.dispatch_id.clone(),
        envelope,
    })
}

fn validate_config(
    task: &TaskSnapshot,
    config: &SingleHarnessWorkConfig,
) -> Result<(), SingleHarnessWorkError> {
    if task.task_id.trim().is_empty() || task.revision == 0 || task.work_revision == 0 {
        return Err(SingleHarnessWorkError::InvalidConfiguration(
            "task snapshot",
        ));
    }
    if config.run_id.trim().is_empty()
        || config.attempt_id.trim().is_empty()
        || config.dispatch_id.trim().is_empty()
        || config.harness_id.trim().is_empty()
        || config.workspace_ref.trim().is_empty()
        || config.owner_instance_id.trim().is_empty()
        || config.plan.steps.len() != 1
        || config.plan.steps[0].step_id.trim().is_empty()
    {
        return Err(SingleHarnessWorkError::InvalidConfiguration(
            "workflow identifiers",
        ));
    }
    if config.task_authority_principal_id.trim().is_empty()
        || config.collaboration_principal_id.trim().is_empty()
        || config.attempt_supervisor_principal_id.trim().is_empty()
        || config.harness_adapter_principal_id.trim().is_empty()
    {
        return Err(SingleHarnessWorkError::InvalidConfiguration(
            "principal identifiers",
        ));
    }
    Ok(())
}

fn create_run_command(
    task: &TaskSnapshot,
    config: &SingleHarnessWorkConfig,
) -> Result<CollaborationCommand, SingleHarnessWorkError> {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::CreateRun(
            CreateRunCommand {
                meta: Some(metadata("create-run", "create-run", &config.run_id)?),
                run_id: config.run_id.clone(),
                task_id: task.task_id.clone(),
                task_revision: task.revision,
                work_revision: task.work_revision,
                plan: Some(config.plan.clone()),
            },
        )),
    };
    seal_request_digest(&mut command).ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    Ok(command)
}

fn activate_run_command(
    snapshot: &CollaborationSnapshot,
    task_revision: u64,
    config: &SingleHarnessWorkConfig,
) -> Result<CollaborationCommand, SingleHarnessWorkError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::ActivateRun(
            ActivateRunCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata("activate-run", "activate-run", &config.run_id)?),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                }),
                confirmed_task_revision: task_revision,
            },
        )),
    };
    seal_request_digest(&mut command).ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    Ok(command)
}

fn create_attempt_command(
    snapshot: &CollaborationSnapshot,
    step_id: &str,
    config: &SingleHarnessWorkConfig,
) -> Result<CollaborationCommand, SingleHarnessWorkError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let step = snapshot
        .steps
        .iter()
        .find(|value| value.step_id == step_id)
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::CreateAttempt(
            CreateAttemptCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata(
                        "create-attempt",
                        "create-attempt",
                        &config.attempt_id,
                    )?),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                }),
                step_id: step.step_id.clone(),
                expected_step_revision: step.revision,
                attempt_id: config.attempt_id.clone(),
                harness_id: config.harness_id.clone(),
                capability_profile_ref: Some(config.capability_profile_ref.clone()),
                workspace_ref: config.workspace_ref.clone(),
            },
        )),
    };
    seal_request_digest(&mut command).ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    Ok(command)
}

fn acquire_lease_command(
    snapshot: &CollaborationSnapshot,
    step_id: &str,
    config: &SingleHarnessWorkConfig,
) -> Result<CollaborationCommand, SingleHarnessWorkError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let step = snapshot
        .steps
        .iter()
        .find(|value| value.step_id == step_id)
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let attempt = snapshot
        .attempts
        .iter()
        .find(|value| value.attempt_id == config.attempt_id)
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::AcquireAttemptLease(
            AcquireAttemptLeaseCommand {
                base: Some(AttemptCommandBase {
                    meta: Some(metadata(
                        "acquire-lease",
                        "acquire-lease",
                        &config.attempt_id,
                    )?),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                    step_id: step.step_id.clone(),
                    expected_step_revision: step.revision,
                    attempt_id: attempt.attempt_id.clone(),
                    expected_attempt_revision: attempt.revision,
                }),
                owner_instance_id: config.owner_instance_id.clone(),
                lease_policy_ref: Some(config.lease_policy_ref.clone()),
            },
        )),
    };
    seal_request_digest(&mut command).ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    Ok(command)
}

fn dispatch_intent_command(
    snapshot: &CollaborationSnapshot,
    step_id: &str,
    config: &SingleHarnessWorkConfig,
) -> Result<CollaborationCommand, SingleHarnessWorkError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let step = snapshot
        .steps
        .iter()
        .find(|value| value.step_id == step_id)
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let attempt = snapshot
        .attempts
        .iter()
        .find(|value| value.attempt_id == config.attempt_id)
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let lease = attempt
        .lease
        .as_ref()
        .ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    let source_meta = metadata(
        "record-dispatch-intent",
        "record-dispatch-intent",
        &attempt.attempt_id,
    )?;
    let mut envelope = DispatchEnvelope {
        meta: Some(CommandMetadata {
            command_id: config.dispatch_id.clone(),
            idempotency_key: config.dispatch_id.clone(),
            idempotency_scope: attempt.attempt_id.clone(),
            request_digest_sha256: String::new(),
            issued_at: source_meta.issued_at,
            correlation_id: source_meta.correlation_id.clone(),
            causation_id: Some(source_meta.command_id.clone()),
        }),
        run_id: run.run_id.clone(),
        run_revision: run.revision + 1,
        step_id: step.step_id.clone(),
        step_revision: step.revision + 1,
        attempt_id: attempt.attempt_id.clone(),
        attempt_revision: attempt.revision + 1,
        dispatch_id: config.dispatch_id.clone(),
        dispatch_fingerprint: String::new(),
        fencing_token: lease.fencing_token,
        capability_profile_ref: attempt.capability_profile_ref.clone(),
        input_bundle_ref: config.plan.steps[0].input_bundle_ref.clone(),
        input_bundle_sha256: config.material.input_bundle_sha256.clone(),
        workspace_ref: attempt.workspace_ref.clone(),
        budget_profile_ref: run
            .plan
            .as_ref()
            .and_then(|value| value.budget_profile_ref.clone()),
        sandbox_profile_ref: Some(config.material.sandbox_profile_ref.clone()),
        tool_policy_ref: Some(config.material.tool_policy_ref.clone()),
        data_egress_policy_ref: Some(config.material.data_egress_policy_ref.clone()),
        approval_policy_ref: Some(config.material.approval_policy_ref.clone()),
        session_strategy: config.material.session_strategy as i32,
        native_session_ref: config.material.native_session_ref.clone(),
        checkpoint_ref: config.material.checkpoint_ref.clone(),
        route_binding: None,
    };
    let fingerprint = canonical_dispatch_fingerprint(&envelope);
    envelope.dispatch_fingerprint = fingerprint.clone();
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordDispatchIntent(
            RecordDispatchIntentCommand {
                base: Some(AttemptCommandBase {
                    meta: Some(source_meta),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                    step_id: step.step_id.clone(),
                    expected_step_revision: step.revision,
                    attempt_id: attempt.attempt_id.clone(),
                    expected_attempt_revision: attempt.revision,
                }),
                lease_id: lease.lease_id.clone(),
                fencing_token: lease.fencing_token,
                dispatch_id: config.dispatch_id.clone(),
                dispatch_fingerprint: fingerprint,
            },
        )),
    };
    seal_request_digest(&mut command).ok_or(SingleHarnessWorkError::MissingSnapshot)?;
    Ok(command)
}

fn snapshot_after<G, C>(
    control: &mut CollaborationControl<G, C>,
    command: &CollaborationCommand,
    principal: &AuthenticatedCollaborationPrincipal,
) -> Result<CollaborationSnapshot, SingleHarnessWorkError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    let result = control.execute(command, principal)?;
    match result.outcome {
        Some(collaboration_command_result::Outcome::Snapshot(snapshot)) => Ok(snapshot),
        Some(collaboration_command_result::Outcome::Error(error)) => Err(
            SingleHarnessWorkError::CommandRejected(error.safe_detail_code),
        ),
        None => Err(SingleHarnessWorkError::MissingSnapshot),
    }
}

fn principal(
    kind: CollaborationPrincipalKind,
    principal_id: &str,
) -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
    }
}

fn metadata(
    command_id: &str,
    idempotency_key: &str,
    scope: &str,
) -> Result<CommandMetadata, SingleHarnessWorkError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SingleHarnessWorkError::Clock)?;
    Ok(CommandMetadata {
        // A workflow retry must address the same command identity. The
        // request timestamp is deliberately volatile and is removed by
        // `seal_request_digest`, but command/idempotency/correlation IDs are
        // durable protocol identity and therefore must not be regenerated.
        command_id: format!("egopulse-{command_id}"),
        idempotency_key: format!("egopulse-{idempotency_key}"),
        idempotency_scope: scope.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
        }),
        correlation_id: format!("egopulse-correlation-{scope}"),
        causation_id: None,
    })
}
