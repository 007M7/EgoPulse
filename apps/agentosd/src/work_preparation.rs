use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_cognition_runtime::context_authority::{
    AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityFailure, ContextPrincipalKind,
    ContextSourceFact, IssueContextSnapshot,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::{CommandMetadata, ContractReference},
    localapi::v1::{
        ConfirmWorkRequest, PrepareWorkRequest, WorkGateNotice, WorkPreparationPreview,
        WorkSourceFact,
    },
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, TaskCommand, TaskCommandResult, TaskStatus,
        task_command, task_command_result,
    },
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPortResult, CommandPrincipal, TaskCommandPort, WorkPreparationPort,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The first real preparation compiler. It is intentionally small and
/// deterministic: source refs are reviewed relative paths under the local
/// workspace, and all authority fields are supplied by this daemon-owned
/// compiler rather than by CLI/TUI input.
pub struct ConfiguredWorkPreparationPort {
    context: Arc<Mutex<ContextAuthority>>,
    task_port: Arc<dyn TaskCommandPort>,
    workspace_root: PathBuf,
    allowed_work_types: BTreeSet<String>,
    acceptance_contract_ref: ContractReference,
    budget_profile_ref: ContractReference,
    /// Reviewed daemon-owned workflow instance used for post-confirmation
    /// activation. None is retained by foundation/unit-test compositions.
    activation_run_id: Option<String>,
}

impl ConfiguredWorkPreparationPort {
    pub fn new(
        context: Arc<Mutex<ContextAuthority>>,
        task_port: Arc<dyn TaskCommandPort>,
        workspace_root: PathBuf,
        allowed_work_types: BTreeSet<String>,
        acceptance_contract_ref: ContractReference,
        budget_profile_ref: ContractReference,
    ) -> Result<Self, CommandPortFailure> {
        let workspace_root = workspace_root
            .canonicalize()
            .map_err(|_| CommandPortFailure::Unavailable)?;
        if allowed_work_types.is_empty()
            || acceptance_contract_ref.contract_id.trim().is_empty()
            || budget_profile_ref.contract_id.trim().is_empty()
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        Ok(Self {
            context,
            task_port,
            workspace_root,
            allowed_work_types,
            acceptance_contract_ref,
            budget_profile_ref,
            activation_run_id: None,
        })
    }

    pub fn with_activation_run_id(mut self, run_id: String) -> Result<Self, CommandPortFailure> {
        if run_id.trim().is_empty() {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        self.activation_run_id = Some(run_id);
        Ok(self)
    }

    fn compile_sources(
        &self,
        request: &PrepareWorkRequest,
    ) -> (Vec<ContextSourceFact>, Vec<WorkGateNotice>, Vec<u8>) {
        let mut facts = Vec::new();
        let mut excluded = Vec::new();
        let mut compiled = Vec::new();
        compiled.extend_from_slice(request.intent.trim().as_bytes());
        compiled.push(b'\n');
        compiled.extend_from_slice(request.work_type.trim().as_bytes());
        compiled.push(b'\n');
        compiled.extend_from_slice(request.target_scope_ref.trim().as_bytes());

        for source in &request.sources {
            let source_ref = source.source_ref.trim();
            if source_ref.is_empty() {
                excluded.push(WorkGateNotice {
                    code: "CONTEXT_SOURCE_EMPTY".to_owned(),
                    detail: "source_ref must not be empty".to_owned(),
                    source_ref: String::new(),
                });
                continue;
            }
            let Some(path) = safe_source_path(&self.workspace_root, source_ref) else {
                excluded.push(WorkGateNotice {
                    code: "CONTEXT_SOURCE_OUTSIDE_WORKSPACE".to_owned(),
                    detail: source_ref.to_owned(),
                    source_ref: source_ref.to_owned(),
                });
                continue;
            };
            let Ok(bytes) = fs::read(&path) else {
                excluded.push(WorkGateNotice {
                    code: "CONTEXT_SOURCE_UNREADABLE".to_owned(),
                    detail: source_ref.to_owned(),
                    source_ref: source_ref.to_owned(),
                });
                continue;
            };
            if bytes.len() > 4 * 1024 * 1024 {
                excluded.push(WorkGateNotice {
                    code: "CONTEXT_SOURCE_TOO_LARGE".to_owned(),
                    detail: source_ref.to_owned(),
                    source_ref: source_ref.to_owned(),
                });
                continue;
            }
            let digest = sha256(&bytes);
            compiled.extend_from_slice(b"\n--SOURCE ");
            compiled.extend_from_slice(source_ref.as_bytes());
            compiled.extend_from_slice(b"--\n");
            compiled.extend_from_slice(&bytes);
            facts.push(ContextSourceFact {
                source_ref: source_ref.to_owned(),
                label: if source.label.trim().is_empty() {
                    source_ref.to_owned()
                } else {
                    source.label.trim().to_owned()
                },
                authority: "project".to_owned(),
                content_sha256: digest,
                included: true,
            });
        }
        (facts, excluded, compiled)
    }

    fn issue_snapshot(
        &self,
        request: &PrepareWorkRequest,
        owner_principal_id: &str,
    ) -> Result<(WorkPreparationPreview, String), CommandPortFailure> {
        if request.intent.trim().is_empty()
            || request.work_type.trim().is_empty()
            || request.target_scope_ref.trim().is_empty()
            || request.idempotency_key.trim().is_empty()
            || !self.allowed_work_types.contains(request.work_type.trim())
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let (sources, excluded_sources, compiled_context) = self.compile_sources(request);
        let recovery_entry = if excluded_sources.is_empty() {
            "hold-and-reconcile"
        } else {
            "blocked-context-source"
        };
        let now = unix_seconds().ok_or(CommandPortFailure::IntegrityFailure)?;
        let expires_at_seconds = now
            .checked_add(60 * 60)
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        let input = IssueContextSnapshot {
            owner_principal_id: owner_principal_id.to_owned(),
            intent: request.intent.trim().to_owned(),
            work_type: request.work_type.trim().to_owned(),
            target_scope_ref: request.target_scope_ref.trim().to_owned(),
            compiled_context,
            sources: sources.clone(),
            memory_pack: None,
            allowed_read_paths: vec![self.workspace_root.display().to_string()],
            allowed_write_paths: vec![self.workspace_root.display().to_string()],
            allowed_tools: Vec::new(),
            external_resources: Vec::new(),
            non_goals: vec![
                "provider/model selection is not made by preparation".to_owned(),
                "memory is not mutated by preparation".to_owned(),
            ],
            acceptance_contract_ref: contract_key(&self.acceptance_contract_ref),
            budget_profile_ref: contract_key(&self.budget_profile_ref),
            deadline_seconds: Some(expires_at_seconds),
            recovery_entry: recovery_entry.to_owned(),
            visibility: "founder-only".to_owned(),
            redactions: Vec::new(),
            expires_at_seconds,
            idempotency_key: request.idempotency_key.trim().to_owned(),
        };
        let principal = AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::ContextCompiler,
            principal_id: "agentosd:work-preparation".to_owned(),
            authenticated: true,
        };
        let (_receipt, snapshot) = self
            .context
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?
            .issue(&input, &principal)
            .map_err(context_failure)?;
        let gate_ready = excluded_sources.is_empty() && !snapshot.sources.is_empty();
        let preview = WorkPreparationPreview {
            snapshot_id: snapshot.snapshot_id.clone(),
            snapshot_revision: snapshot.revision,
            normalized_intent: snapshot.intent,
            work_type: snapshot.work_type,
            target_scope_ref: snapshot.target_scope_ref,
            compiled_context_sha256: snapshot.compiled_context_sha256,
            included_sources: sources.into_iter().map(source_fact).collect(),
            excluded_sources: excluded_sources.clone(),
            non_goals: snapshot.non_goals,
            allowed_read_paths: snapshot.allowed_read_paths,
            allowed_write_paths: snapshot.allowed_write_paths,
            allowed_tools: snapshot.allowed_tools,
            external_resources: snapshot.external_resources,
            acceptance_contract_ref: Some(self.acceptance_contract_ref.clone()),
            budget_profile_ref: Some(self.budget_profile_ref.clone()),
            memory_authority_revision: None,
            memory_pack_snapshot_sha256: None,
            recovery_entry: snapshot.recovery_entry,
            visibility: snapshot.visibility,
            redactions: Vec::new(),
            expires_at: Some(Timestamp {
                seconds: snapshot.expires_at_seconds,
                nanos: 0,
            }),
            confirmation_binding_sha256: snapshot.confirmation_binding_sha256,
            gate_ready,
            blockers: excluded_sources.clone(),
            warnings: Vec::new(),
            required_confirmations: vec!["founder.confirm_work".to_owned()],
            evidence_required: vec![
                "artifact_and_evidence".to_owned(),
                "sego_verification".to_owned(),
                "founder_verdict".to_owned(),
            ],
            ready_for_founder_confirmation: gate_ready,
            deadline: Some(Timestamp {
                seconds: expires_at_seconds,
                nanos: 0,
            }),
        };
        Ok((preview, snapshot.snapshot_id))
    }
}

impl WorkPreparationPort for ConfiguredWorkPreparationPort {
    fn prepare(
        &self,
        request: &PrepareWorkRequest,
        principal: &CommandPrincipal,
    ) -> Result<WorkPreparationPreview, CommandPortFailure> {
        self.issue_snapshot(request, &principal.principal_id)
            .map(|(preview, _)| preview)
    }

    fn confirm(
        &self,
        request: &ConfirmWorkRequest,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        if request.snapshot_id.trim().is_empty()
            || request.confirmation_binding_sha256.trim().is_empty()
            || request.idempotency_key.trim().is_empty()
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let now = unix_seconds().ok_or(CommandPortFailure::IntegrityFailure)?;
        let snapshot = self
            .context
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?
            .get(&request.snapshot_id)
            .map_err(context_failure)?
            .ok_or(CommandPortFailure::Unavailable)?;
        if snapshot.confirmation_binding_sha256 != request.confirmation_binding_sha256
            || snapshot.owner_principal_id != principal.principal_id
            || !snapshot.sources.iter().all(|source| source.included)
            || snapshot.sources.is_empty()
            || snapshot.recovery_entry != "hold-and-reconcile"
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let resolved = self
            .context
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?
            .resolve(&request.snapshot_id, &snapshot.target_scope_ref, now)
            .map_err(context_failure)?;
        if resolved.snapshot.confirmation_binding_sha256 != request.confirmation_binding_sha256 {
            return Err(CommandPortFailure::IntegrityFailure);
        }

        let correlation_id = request
            .client
            .as_ref()
            .and_then(|value| value.correlation_id.clone())
            .unwrap_or_else(|| Uuid::now_v7().to_string());
        let mut command = TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(CommandMetadata {
                    command_id: Uuid::now_v7().to_string(),
                    idempotency_key: request.idempotency_key.clone(),
                    idempotency_scope: "local.work.confirm".to_owned(),
                    request_digest_sha256: String::new(),
                    issued_at: Some(Timestamp {
                        seconds: now,
                        nanos: 0,
                    }),
                    correlation_id,
                    causation_id: Some(request.snapshot_id.clone()),
                }),
                work_type: resolved.snapshot.work_type,
                input_snapshot_id: resolved.snapshot.snapshot_id,
                target_scope_ref: resolved.snapshot.target_scope_ref,
                acceptance_contract_ref: Some(self.acceptance_contract_ref.clone()),
                budget_profile_ref: Some(self.budget_profile_ref.clone()),
            })),
        };
        set_task_digest(&mut command);
        let created = self.task_port.execute(&command, principal)?;
        let Some(run_id) = self.activation_run_id.as_deref() else {
            return Ok(created);
        };
        let Some(task) = created
            .result
            .outcome
            .as_ref()
            .and_then(|outcome| match outcome {
                task_command_result::Outcome::Task(task) => Some(task),
                task_command_result::Outcome::Error(_) => None,
            })
        else {
            return Ok(created);
        };
        if task.status != TaskStatus::Ready as i32 {
            return Ok(created);
        }

        // Founder confirmation creates the Task. Activation is a separate,
        // daemon-owned settlement against the reviewed workflow. The client
        // cannot submit or widen this system operation. A stable derived
        // idempotency key repairs the CreateTask/ActivateTask crash window
        // when the same confirmation is retried.
        let mut activation = TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(CommandMetadata {
                    command_id: Uuid::now_v7().to_string(),
                    idempotency_key: format!("{}:activate", request.idempotency_key),
                    idempotency_scope: "local.work.confirm.activation".to_owned(),
                    request_digest_sha256: String::new(),
                    issued_at: Some(Timestamp {
                        seconds: now,
                        nanos: 0,
                    }),
                    correlation_id: task.task_id.clone(),
                    causation_id: Some(request.snapshot_id.clone()),
                }),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                work_revision: task.work_revision,
                run_id: run_id.to_owned(),
            })),
        };
        set_activation_digest(&mut activation);
        match self.task_port.execute_system_activation(&activation) {
            Ok(activated)
                if matches!(
                    &activated.result.outcome,
                    Some(task_command_result::Outcome::Task(_))
                ) =>
            {
                Ok(activated)
            }
            // Creation is already durable. Preserve the honest Ready result
            // if the reviewed workflow cannot be activated yet; a retry can
            // reconcile it without reporting a false execution.
            Ok(_) | Err(_) => Ok(created),
        }
    }
}

fn safe_source_path(root: &Path, source_ref: &str) -> Option<PathBuf> {
    let candidate = Path::new(source_ref);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return None;
    }
    let path = root.join(candidate).canonicalize().ok()?;
    path.starts_with(root).then_some(path)
}

fn source_fact(source: ContextSourceFact) -> WorkSourceFact {
    WorkSourceFact {
        source_ref: source.source_ref,
        label: source.label,
        authority: source.authority,
        content_sha256: source.content_sha256,
        included: source.included,
    }
}

fn contract_key(reference: &ContractReference) -> String {
    format!(
        "{}@{}#{}",
        reference.contract_id, reference.version, reference.sha256
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unix_seconds() -> Option<i64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

fn context_failure(error: ContextAuthorityFailure) -> CommandPortFailure {
    match error {
        ContextAuthorityFailure::Storage | ContextAuthorityFailure::IntegrityFailure => {
            CommandPortFailure::IntegrityFailure
        }
        ContextAuthorityFailure::NotFound
        | ContextAuthorityFailure::Expired
        | ContextAuthorityFailure::Revoked
        | ContextAuthorityFailure::ScopeMismatch
        | ContextAuthorityFailure::InvalidArgument(_)
        | ContextAuthorityFailure::Unauthorized
        | ContextAuthorityFailure::IdempotencyConflict
        | ContextAuthorityFailure::Clock => CommandPortFailure::IntegrityFailure,
    }
}

fn set_task_digest(command: &mut TaskCommand) {
    let mut canonical = command.clone();
    if let Some(task_command::Command::CreateTask(create)) = canonical.command.as_mut() {
        if let Some(metadata) = create.meta.as_mut() {
            metadata.command_id.clear();
            metadata.request_digest_sha256.clear();
            metadata.issued_at = None;
            metadata.correlation_id.clear();
            metadata.causation_id = None;
        }
    }
    let digest = sha256(&canonical.encode_to_vec());
    if let Some(task_command::Command::CreateTask(create)) = command.command.as_mut() {
        create
            .meta
            .as_mut()
            .expect("metadata exists")
            .request_digest_sha256 = digest;
    }
}

fn set_activation_digest(command: &mut TaskCommand) {
    let mut canonical = command.clone();
    if let Some(task_command::Command::ActivateTask(activate)) = canonical.command.as_mut() {
        if let Some(metadata) = activate.meta.as_mut() {
            metadata.command_id.clear();
            metadata.request_digest_sha256.clear();
            metadata.issued_at = None;
        }
    }
    let digest = sha256(&canonical.encode_to_vec());
    if let Some(task_command::Command::ActivateTask(activate)) = command.command.as_mut() {
        activate
            .meta
            .as_mut()
            .expect("metadata exists")
            .request_digest_sha256 = digest;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkSourceRequest;
    use std::sync::Mutex;
    use std::time::Duration;

    struct RecordingTaskPort {
        commands: Mutex<Vec<TaskCommand>>,
        return_task_snapshots: Mutex<bool>,
    }

    impl TaskCommandPort for RecordingTaskPort {
        fn execute(
            &self,
            command: &TaskCommand,
            _principal: &CommandPrincipal,
        ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
            self.commands
                .lock()
                .expect("recording port lock")
                .push(command.clone());
            if *self
                .return_task_snapshots
                .lock()
                .expect("recording task mode lock")
            {
                let snapshot = match &command.command {
                    Some(task_command::Command::CreateTask(_)) => {
                        egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                            task_id: "task-work-preparation".to_owned(),
                            revision: 1,
                            work_revision: 1,
                            status: TaskStatus::Ready as i32,
                            ..Default::default()
                        }
                    }
                    Some(task_command::Command::ActivateTask(value)) => {
                        egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                            task_id: value.task_id.clone(),
                            revision: value.expected_revision + 1,
                            work_revision: value.work_revision,
                            status: TaskStatus::Active as i32,
                            current_run_id: Some(value.run_id.clone()),
                            ..Default::default()
                        }
                    }
                    _ => unreachable!("work preparation recording port command"),
                };
                return Ok(CommandPortResult {
                    result: TaskCommandResult {
                        outcome: Some(task_command_result::Outcome::Task(snapshot)),
                        ..Default::default()
                    },
                    source_revision: None,
                    await_target: None,
                });
            }
            Ok(CommandPortResult {
                result: TaskCommandResult::default(),
                source_revision: None,
                await_target: None,
            })
        }

        fn execute_system_activation(
            &self,
            command: &TaskCommand,
        ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
            self.execute(
                command,
                &CommandPrincipal {
                    principal_id: "test-system".to_owned(),
                    required_authority_principal_kinds: Vec::new(),
                },
            )
        }
    }

    struct WorkFixture {
        root: std::path::PathBuf,
        context: Arc<Mutex<ContextAuthority>>,
        task_port: Arc<RecordingTaskPort>,
        port: ConfiguredWorkPreparationPort,
    }

    impl WorkFixture {
        fn open(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("egopulse-work-{tag}-{}", Uuid::now_v7()));
            fs::create_dir_all(&root).expect("workspace");
            fs::write(root.join("intent.md"), "founder-owned source").expect("source file");
            let context = Arc::new(Mutex::new(
                ContextAuthority::open(
                    egopulse_cognition_runtime::context_authority::ContextAuthorityConfig {
                        database_path: root.join("context.db"),
                        store_epoch: format!("test-context-{tag}"),
                        key: egopulse_cognition_runtime::task_authority::SqlCipherKey::new([7; 32]),
                    },
                )
                .expect("context authority"),
            ));
            let task_port = Arc::new(RecordingTaskPort {
                commands: Mutex::new(Vec::new()),
                return_task_snapshots: Mutex::new(false),
            });
            let port = ConfiguredWorkPreparationPort::new(
                Arc::clone(&context),
                Arc::clone(&task_port) as Arc<dyn TaskCommandPort>,
                root.clone(),
                BTreeSet::from(["governed_repository_change".to_owned()]),
                contract("acceptance"),
                contract("budget"),
            )
            .expect("work preparation port");
            Self {
                root,
                context,
                task_port,
                port,
            }
        }

        fn founder(id: &str) -> CommandPrincipal {
            CommandPrincipal {
                principal_id: id.to_owned(),
                required_authority_principal_kinds: Vec::new(),
            }
        }

        fn prepare_request(
            &self,
            intent: &str,
            idempotency_key: &str,
            sources: Vec<WorkSourceRequest>,
        ) -> PrepareWorkRequest {
            PrepareWorkRequest {
                intent: intent.to_owned(),
                work_type: "governed_repository_change".to_owned(),
                target_scope_ref: "project:egopulse".to_owned(),
                sources,
                idempotency_key: idempotency_key.to_owned(),
                ..Default::default()
            }
        }

        fn confirm_request(
            &self,
            preview: &WorkPreparationPreview,
            idempotency_key: &str,
        ) -> ConfirmWorkRequest {
            ConfirmWorkRequest {
                snapshot_id: preview.snapshot_id.clone(),
                confirmation_binding_sha256: preview.confirmation_binding_sha256.clone(),
                idempotency_key: idempotency_key.to_owned(),
                ..Default::default()
            }
        }

        fn delegated_command_count(&self) -> usize {
            self.task_port
                .commands
                .lock()
                .expect("recording port lock")
                .len()
        }

        fn enable_activation(&self) {
            *self
                .task_port
                .return_task_snapshots
                .lock()
                .expect("recording task mode lock") = true;
        }

        fn finish(self) {
            let Self {
                root,
                context,
                task_port,
                port,
            } = self;
            drop(port);
            drop(task_port);
            drop(context);
            let _ = fs::remove_dir_all(&root);
        }
    }

    fn contract(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn create_meta(command: &TaskCommand) -> &CommandMetadata {
        match &command.command {
            Some(task_command::Command::CreateTask(create)) => {
                create.meta.as_ref().expect("metadata")
            }
            _ => panic!("expected a delegated create task command"),
        }
    }

    #[test]
    fn preparation_reads_reviewed_workspace_and_confirmation_delegates_task_creation() {
        let fixture = WorkFixture::open("happy");
        let principal = WorkFixture::founder("founder-1");
        let request = fixture.prepare_request(
            "update the governed source",
            "prepare-1",
            vec![WorkSourceRequest {
                source_ref: "intent.md".to_owned(),
                label: "intent".to_owned(),
            }],
        );
        let preview = fixture.port.prepare(&request, &principal).expect("preview");
        assert!(preview.gate_ready);
        assert_eq!(preview.included_sources.len(), 1);
        assert!(!preview.confirmation_binding_sha256.is_empty());

        let result = fixture
            .port
            .confirm(&fixture.confirm_request(&preview, "confirm-1"), &principal)
            .expect("confirmation delegates");
        assert!(result.result.outcome.is_none());
        let commands = fixture
            .task_port
            .commands
            .lock()
            .expect("recording port lock");
        assert_eq!(commands.len(), 1);
        assert!(matches!(
            commands[0].command,
            Some(task_command::Command::CreateTask(_))
        ));
        drop(commands);
        fixture.finish();
    }

    #[test]
    fn confirmation_settles_daemon_owned_activation_when_workflow_is_configured() {
        let mut fixture = WorkFixture::open("activation");
        fixture.enable_activation();
        let principal = WorkFixture::founder("founder-1");
        fixture.port = fixture
            .port
            .with_activation_run_id("reviewed-run-001".to_owned())
            .expect("reviewed activation run");
        let preview = fixture
            .port
            .prepare(
                &fixture.prepare_request(
                    "run the governed source workflow",
                    "prepare-activation",
                    vec![WorkSourceRequest {
                        source_ref: "intent.md".to_owned(),
                        label: "intent".to_owned(),
                    }],
                ),
                &principal,
            )
            .expect("preview");
        let result = fixture
            .port
            .confirm(
                &fixture.confirm_request(&preview, "confirm-activation"),
                &principal,
            )
            .expect("confirmation and activation");
        let task = match result.result.outcome.expect("activation result") {
            task_command_result::Outcome::Task(task) => task,
            task_command_result::Outcome::Error(error) => {
                panic!("unexpected activation error: {}", error.safe_detail_code)
            }
        };
        assert_eq!(task.status, TaskStatus::Active as i32);
        assert_eq!(task.current_run_id.as_deref(), Some("reviewed-run-001"));
        let commands = fixture
            .task_port
            .commands
            .lock()
            .expect("recording port lock");
        assert_eq!(commands.len(), 2);
        assert!(matches!(
            commands[0].command,
            Some(task_command::Command::CreateTask(_))
        ));
        assert!(matches!(
            commands[1].command,
            Some(task_command::Command::ActivateTask(_))
        ));
        drop(commands);
        fixture.finish();
    }

    #[test]
    fn confirm_with_altered_or_swapped_binding_fails_closed_without_delegation() {
        let fixture = WorkFixture::open("altered-binding");
        let principal = WorkFixture::founder("founder-1");
        let source = vec![WorkSourceRequest {
            source_ref: "intent.md".to_owned(),
            label: "intent".to_owned(),
        }];
        let first = fixture
            .port
            .prepare(
                &fixture.prepare_request("first intent", "prepare-altered", source.clone()),
                &principal,
            )
            .expect("first preview");
        let second = fixture
            .port
            .prepare(
                &fixture.prepare_request("second intent", "prepare-other", source),
                &principal,
            )
            .expect("second preview");
        assert_ne!(
            first.confirmation_binding_sha256, second.confirmation_binding_sha256,
            "two different intents must not share one binding"
        );

        let mut altered = fixture.confirm_request(&first, "confirm-altered");
        altered.confirmation_binding_sha256 = "f".repeat(64);
        let error = fixture
            .port
            .confirm(&altered, &principal)
            .expect_err("an altered binding must not confirm");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));

        let mut swapped = fixture.confirm_request(&first, "confirm-swapped");
        swapped.confirmation_binding_sha256 = second.confirmation_binding_sha256.clone();
        let error = fixture
            .port
            .confirm(&swapped, &principal)
            .expect_err("another snapshot's binding must not confirm this one");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));
        assert_eq!(
            fixture.delegated_command_count(),
            0,
            "no Task command may leave the preparation boundary"
        );
        fixture.finish();
    }

    #[test]
    fn confirm_rejects_a_blocked_context_source_snapshot() {
        let fixture = WorkFixture::open("blocked-source");
        let principal = WorkFixture::founder("founder-1");
        let preview = fixture
            .port
            .prepare(
                &fixture.prepare_request(
                    "update the governed source",
                    "prepare-blocked",
                    vec![
                        WorkSourceRequest {
                            source_ref: "intent.md".to_owned(),
                            label: "intent".to_owned(),
                        },
                        WorkSourceRequest {
                            source_ref: "../secrets.txt".to_owned(),
                            label: "escape".to_owned(),
                        },
                    ],
                ),
                &principal,
            )
            .expect("a blocked preview is still issued for display");
        assert!(!preview.gate_ready);
        assert!(!preview.ready_for_founder_confirmation);
        assert_eq!(preview.blockers.len(), 1);
        assert_eq!(preview.blockers[0].code, "CONTEXT_SOURCE_OUTSIDE_WORKSPACE");
        assert_eq!(preview.blockers[0].source_ref, "../secrets.txt");
        assert_eq!(preview.excluded_sources[0].source_ref, "../secrets.txt");

        let error = fixture
            .port
            .confirm(
                &fixture.confirm_request(&preview, "confirm-blocked"),
                &principal,
            )
            .expect_err("a blocked context snapshot must not confirm");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));
        assert_eq!(fixture.delegated_command_count(), 0);
        fixture.finish();
    }

    #[test]
    fn confirm_from_a_different_principal_fails_closed() {
        let fixture = WorkFixture::open("cross-principal");
        let preparer = WorkFixture::founder("founder-1");
        let preview = fixture
            .port
            .prepare(
                &fixture.prepare_request(
                    "update the governed source",
                    "prepare-cross",
                    vec![WorkSourceRequest {
                        source_ref: "intent.md".to_owned(),
                        label: "intent".to_owned(),
                    }],
                ),
                &preparer,
            )
            .expect("preview");
        let other = WorkFixture::founder("founder-2");
        let error = fixture
            .port
            .confirm(&fixture.confirm_request(&preview, "confirm-cross"), &other)
            .expect_err("another principal must not confirm this snapshot");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));
        assert_eq!(fixture.delegated_command_count(), 0);

        fixture
            .port
            .confirm(
                &fixture.confirm_request(&preview, "confirm-cross-owner"),
                &preparer,
            )
            .expect("the owning principal can still confirm");
        assert_eq!(fixture.delegated_command_count(), 1);
        fixture.finish();
    }

    #[test]
    fn confirm_after_snapshot_expiry_fails_closed() {
        let fixture = WorkFixture::open("expired");
        let owner = WorkFixture::founder("founder-1");
        // The port hardcodes a one-hour preparation expiry, so the expiring
        // snapshot is issued directly through the same Authority the port
        // consults; the port's confirm path then consumes it.
        let now = unix_seconds().expect("clock");
        let input = IssueContextSnapshot {
            owner_principal_id: "founder-1".to_owned(),
            intent: "expiring intent".to_owned(),
            work_type: "governed_repository_change".to_owned(),
            target_scope_ref: "project:egopulse".to_owned(),
            compiled_context: b"expiring intent\ngoverned_repository_change\nproject:egopulse"
                .to_vec(),
            sources: vec![ContextSourceFact {
                source_ref: "intent.md".to_owned(),
                label: "intent".to_owned(),
                authority: "project".to_owned(),
                content_sha256: sha256(b"founder-owned source"),
                included: true,
            }],
            memory_pack: None,
            allowed_read_paths: vec![fixture.root.display().to_string()],
            allowed_write_paths: vec![fixture.root.display().to_string()],
            allowed_tools: Vec::new(),
            external_resources: Vec::new(),
            non_goals: Vec::new(),
            acceptance_contract_ref: contract_key(&contract("acceptance")),
            budget_profile_ref: contract_key(&contract("budget")),
            deadline_seconds: None,
            recovery_entry: "hold-and-reconcile".to_owned(),
            visibility: "founder-only".to_owned(),
            redactions: Vec::new(),
            expires_at_seconds: now + 1,
            idempotency_key: "prepare-expiring".to_owned(),
        };
        let compiler = AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::ContextCompiler,
            principal_id: "agentosd:work-preparation".to_owned(),
            authenticated: true,
        };
        let (_, snapshot) = fixture
            .context
            .lock()
            .expect("context lock")
            .issue(&input, &compiler)
            .expect("direct issue");
        std::thread::sleep(Duration::from_millis(1200));

        let request = ConfirmWorkRequest {
            snapshot_id: snapshot.snapshot_id.clone(),
            confirmation_binding_sha256: snapshot.confirmation_binding_sha256.clone(),
            idempotency_key: "confirm-expired".to_owned(),
            ..Default::default()
        };
        let error = fixture
            .port
            .confirm(&request, &owner)
            .expect_err("an expired snapshot must not confirm");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));
        assert_eq!(fixture.delegated_command_count(), 0);
        fixture.finish();
    }

    #[test]
    fn replayed_confirmation_carries_one_idempotent_command_identity() {
        let fixture = WorkFixture::open("replay");
        let principal = WorkFixture::founder("founder-1");
        let preview = fixture
            .port
            .prepare(
                &fixture.prepare_request(
                    "update the governed source",
                    "prepare-replay",
                    vec![WorkSourceRequest {
                        source_ref: "intent.md".to_owned(),
                        label: "intent".to_owned(),
                    }],
                ),
                &principal,
            )
            .expect("preview");
        fixture
            .port
            .confirm(
                &fixture.confirm_request(&preview, "confirm-replay"),
                &principal,
            )
            .expect("first confirmation");
        fixture
            .port
            .confirm(
                &fixture.confirm_request(&preview, "confirm-replay"),
                &principal,
            )
            .expect("replayed confirmation still reaches the authority");
        // The replay verdict itself belongs to Task Authority (covered by the
        // cognition-runtime idempotency tests); this boundary only has to
        // present one idempotent identity for every delegation.
        let commands = fixture
            .task_port
            .commands
            .lock()
            .expect("recording port lock");
        assert_eq!(commands.len(), 2);
        let (first, second) = (create_meta(&commands[0]), create_meta(&commands[1]));
        assert_ne!(first.command_id, second.command_id);
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert_eq!(first.idempotency_scope, "local.work.confirm");
        assert_eq!(second.idempotency_scope, "local.work.confirm");
        assert_eq!(
            first.request_digest_sha256, second.request_digest_sha256,
            "every delegation of one confirmation must present one canonical digest"
        );
        drop(commands);
        fixture.finish();
    }
}
