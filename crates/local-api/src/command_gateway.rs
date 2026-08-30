use std::sync::Arc;

use egopulse_domain_contracts::{
    profiles::{AuthorizedCommand, ContractProfileError, ContractProfiles},
    v01::egopulse::{
        common::v1::CommandMetadata,
        localapi::v1::{
            ClientRequestMetadata, ConfirmWorkRequest, ConfirmWorkResponse,
            DecideHarnessApprovalRequest, DecideHarnessApprovalResponse,
            ExecuteContextMutationRequest, ExecuteContextMutationResponse,
            ExecuteFounderVerdictRequest, ExecuteFounderVerdictResponse,
            ExecuteMemoryMutationRequest, ExecuteMemoryMutationResponse, ExecuteTaskCommandRequest,
            ExecuteTaskCommandResponse, HarnessApprovalAuthorityResult, LocalApiError,
            LocalApiErrorCode, MemoryMutationCommand, MemoryMutationReceipt, PrepareWorkRequest,
            PrepareWorkResponse, ProjectionAwaitToken, SourceRevision, WorkPreparationPreview,
            confirm_work_response, execute_context_mutation_response,
            local_command_gateway_service_server::LocalCommandGatewayService,
            prepare_work_response,
        },
        policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
        task::v1::{TaskCommand, TaskCommandResult, task_command},
        verdict::v1::{VerdictCommand, VerdictCommandResult, verdict_command},
    },
};
use egopulse_local_ipc_platform::PeerConnectionInfo;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    read_tokens::{AwaitTarget, ReadTokenCodec, ReadTokenScope},
    session::{AuthenticatedSession, SessionAuthenticationFailure, SessionRegistry},
};

const RPC_EXECUTE_TASK: &str = "LocalCommandGatewayService/ExecuteTaskCommand";
const RPC_DECIDE_APPROVAL: &str = "LocalCommandGatewayService/DecideHarnessApproval";
const RPC_EXECUTE_VERDICT: &str = "LocalCommandGatewayService/ExecuteFounderVerdict";
const RPC_EXECUTE_MEMORY: &str = "LocalCommandGatewayService/ExecuteMemoryMutation";
const RPC_PREPARE_WORK: &str = "LocalCommandGatewayService/PrepareWork";
const RPC_CONFIRM_WORK: &str = "LocalCommandGatewayService/ConfirmWork";

/// The principal boundary passed from the governed Local API session into an
/// owning Authority adapter. The gateway never constructs an Authority
/// implementation or reads an Authority store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPrincipal {
    pub principal_id: String,
    /// The profile's accepted Authority principal kinds are propagated as a
    /// set of constraints. The gateway must not select one because a Local
    /// Session does not authenticate an Authority principal kind.
    pub required_authority_principal_kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPortResult<R> {
    pub result: R,
    /// A port supplies this only when the Authority has durably committed (or
    /// replayed) a change that has a Local Read Model target.
    pub source_revision: Option<SourceRevision>,
    pub await_target: Option<AwaitTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandPortFailure {
    Unavailable,
    /// The owner may have committed an external side effect, but the result
    /// of delivery is not known. Callers must reconcile before retrying.
    DeliveryUnknown,
    IntegrityFailure,
}

pub trait TaskCommandPort: Send + Sync + 'static {
    fn execute(
        &self,
        command: &TaskCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure>;

    /// Daemon-owned system activation over one reviewed ActivateTask command.
    /// The principal is owned by the implementing port, never by the caller.
    /// The default is fail-closed: a port that does not explicitly admit
    /// system activation must reject it.
    fn execute_system_activation(
        &self,
        command: &TaskCommand,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        let _ = command;
        Err(CommandPortFailure::Unavailable)
    }
}

pub trait PolicyCommandPort: Send + Sync + 'static {
    fn execute(
        &self,
        command: &IssueHarnessApprovalDecisionCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure>;
}

pub trait VerdictCommandPort: Send + Sync + 'static {
    fn execute(
        &self,
        command: &VerdictCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure>;
}

/// The gateway passes an explicit Memory command to its owning Authority
/// adapter. It never chooses an Authority principal or opens a store.
pub trait MemoryMutationPort: Send + Sync + 'static {
    fn execute(
        &self,
        command: &MemoryMutationCommand,
        principal: &CommandPrincipal,
    ) -> Result<MemoryMutationReceipt, CommandPortFailure>;
}

#[derive(Default)]
pub struct FailClosedMemoryMutationPort;

impl MemoryMutationPort for FailClosedMemoryMutationPort {
    fn execute(
        &self,
        _command: &MemoryMutationCommand,
        _principal: &CommandPrincipal,
    ) -> Result<MemoryMutationReceipt, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

/// Preparation and confirmation are routed to the owning daemon composition.
/// The Local API deliberately has no Context/Task store and cannot compile a
/// client-authored snapshot. Implementations must prove the snapshot and then
/// delegate confirmation to the Task Authority.
pub trait WorkPreparationPort: Send + Sync + 'static {
    fn prepare(
        &self,
        request: &PrepareWorkRequest,
        principal: &CommandPrincipal,
    ) -> Result<WorkPreparationPreview, CommandPortFailure>;

    fn confirm(
        &self,
        request: &ConfirmWorkRequest,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure>;
}

#[derive(Default)]
pub struct FailClosedWorkPreparationPort;

impl WorkPreparationPort for FailClosedWorkPreparationPort {
    fn prepare(
        &self,
        _request: &PrepareWorkRequest,
        _principal: &CommandPrincipal,
    ) -> Result<WorkPreparationPreview, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }

    fn confirm(
        &self,
        _request: &ConfirmWorkRequest,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

pub struct CommandGatewayApplication {
    registry: Arc<SessionRegistry>,
    profiles: Arc<ContractProfiles>,
    token_codec: Arc<ReadTokenCodec>,
    task_port: Arc<dyn TaskCommandPort>,
    policy_port: Arc<dyn PolicyCommandPort>,
    verdict_port: Arc<dyn VerdictCommandPort>,
    memory_port: Arc<dyn MemoryMutationPort>,
    work_port: Arc<dyn WorkPreparationPort>,
}

pub struct CommandExtensionPorts {
    memory: Arc<dyn MemoryMutationPort>,
    work: Arc<dyn WorkPreparationPort>,
}

impl CommandExtensionPorts {
    #[must_use]
    pub fn new(memory: Arc<dyn MemoryMutationPort>, work: Arc<dyn WorkPreparationPort>) -> Self {
        Self { memory, work }
    }
}

impl CommandGatewayApplication {
    #[must_use]
    pub fn new(
        registry: Arc<SessionRegistry>,
        profiles: Arc<ContractProfiles>,
        token_codec: Arc<ReadTokenCodec>,
        task_port: Arc<dyn TaskCommandPort>,
        policy_port: Arc<dyn PolicyCommandPort>,
        verdict_port: Arc<dyn VerdictCommandPort>,
    ) -> Self {
        Self::new_with_memory(
            registry,
            profiles,
            token_codec,
            task_port,
            policy_port,
            verdict_port,
            Arc::new(FailClosedMemoryMutationPort),
        )
    }

    #[must_use]
    pub fn new_with_memory(
        registry: Arc<SessionRegistry>,
        profiles: Arc<ContractProfiles>,
        token_codec: Arc<ReadTokenCodec>,
        task_port: Arc<dyn TaskCommandPort>,
        policy_port: Arc<dyn PolicyCommandPort>,
        verdict_port: Arc<dyn VerdictCommandPort>,
        memory_port: Arc<dyn MemoryMutationPort>,
    ) -> Self {
        Self::new_with_memory_and_work(
            registry,
            profiles,
            token_codec,
            task_port,
            policy_port,
            verdict_port,
            CommandExtensionPorts::new(memory_port, Arc::new(FailClosedWorkPreparationPort)),
        )
    }

    #[must_use]
    pub fn new_with_memory_and_work(
        registry: Arc<SessionRegistry>,
        profiles: Arc<ContractProfiles>,
        token_codec: Arc<ReadTokenCodec>,
        task_port: Arc<dyn TaskCommandPort>,
        policy_port: Arc<dyn PolicyCommandPort>,
        verdict_port: Arc<dyn VerdictCommandPort>,
        extensions: CommandExtensionPorts,
    ) -> Self {
        Self {
            registry,
            profiles,
            token_codec,
            task_port,
            policy_port,
            verdict_port,
            memory_port: extensions.memory,
            work_port: extensions.work,
        }
    }

    pub fn prepare_work(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: PrepareWorkRequest,
    ) -> PrepareWorkResponse {
        let correlation_id = client_correlation_id(request.client.as_ref());
        let context = match self.authorize_rpc(peer, request.client.as_ref(), RPC_PREPARE_WORK) {
            Ok(context) => context,
            Err(error) => {
                return PrepareWorkResponse {
                    outcome: Some(prepare_work_response::Outcome::Error(
                        (*error).with_correlation(correlation_id),
                    )),
                };
            }
        };
        match self.work_port.prepare(&request, &context.principal) {
            Ok(preview) => PrepareWorkResponse {
                outcome: Some(prepare_work_response::Outcome::Preview(preview)),
            },
            Err(error) => PrepareWorkResponse {
                outcome: Some(prepare_work_response::Outcome::Error(port_error(
                    error,
                    correlation_id,
                ))),
            },
        }
    }

    pub fn confirm_work(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: ConfirmWorkRequest,
    ) -> ConfirmWorkResponse {
        let correlation_id = client_correlation_id(request.client.as_ref());
        let context = match self.authorize_rpc(peer, request.client.as_ref(), RPC_CONFIRM_WORK) {
            Ok(context) => context,
            Err(error) => {
                return ConfirmWorkResponse {
                    outcome: Some(confirm_work_response::Outcome::Error(
                        (*error).with_correlation(correlation_id),
                    )),
                };
            }
        };
        match self.work_port.confirm(&request, &context.principal) {
            Ok(port_result) => {
                let (await_token, gateway_error) = self.issue_await_token(
                    &context.session,
                    port_result.source_revision,
                    port_result.await_target,
                    correlation_id,
                );
                ConfirmWorkResponse {
                    outcome: Some(match gateway_error {
                        Some(error) => confirm_work_response::Outcome::Error(error),
                        None => confirm_work_response::Outcome::Accepted(
                            egopulse_domain_contracts::v01::egopulse::localapi::v1::ConfirmWorkAccepted {
                                authority_result: Some(port_result.result),
                                await_token,
                            },
                        ),
                    }),
                }
            }
            Err(error) => ConfirmWorkResponse {
                outcome: Some(confirm_work_response::Outcome::Error(port_error(
                    error,
                    correlation_id,
                ))),
            },
        }
    }

    pub fn execute_task_command(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: ExecuteTaskCommandRequest,
    ) -> ExecuteTaskCommandResponse {
        let correlation_id =
            command_correlation_id(request.client.as_ref(), request.command.as_ref());
        let context = match self.authorize(
            peer,
            request.client.as_ref(),
            RPC_EXECUTE_TASK,
            task_oneof(request.command.as_ref()),
        ) {
            Ok(context) => context,
            Err(error) => {
                return ExecuteTaskCommandResponse {
                    authority_result: None,
                    await_token: None,
                    gateway_error: Some((*error).with_correlation(correlation_id)),
                };
            }
        };
        let Some(command) = request.command else {
            return ExecuteTaskCommandResponse {
                authority_result: None,
                await_token: None,
                gateway_error: Some(invalid_error("command_missing", correlation_id)),
            };
        };
        if let Err(error) =
            validate_command_metadata(request.client.as_ref(), task_metadata(&command))
        {
            return ExecuteTaskCommandResponse {
                authority_result: None,
                await_token: None,
                gateway_error: Some((*error).with_correlation(correlation_id)),
            };
        }
        match self.task_port.execute(&command, &context.principal) {
            Ok(port_result) => {
                let (await_token, gateway_error) = self.issue_await_token(
                    &context.session,
                    port_result.source_revision,
                    port_result.await_target,
                    correlation_id,
                );
                ExecuteTaskCommandResponse {
                    await_token,
                    gateway_error,
                    authority_result: Some(port_result.result),
                }
            }
            Err(error) => ExecuteTaskCommandResponse {
                authority_result: None,
                await_token: None,
                gateway_error: Some(port_error(error, correlation_id)),
            },
        }
    }

    #[allow(deprecated)]
    pub fn decide_harness_approval(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: DecideHarnessApprovalRequest,
    ) -> DecideHarnessApprovalResponse {
        let correlation_id =
            command_correlation_id(request.client.as_ref(), request.command.as_ref());
        let context = match self.authorize(
            peer,
            request.client.as_ref(),
            RPC_DECIDE_APPROVAL,
            request
                .command
                .as_ref()
                .map(|_| "issue_harness_approval_decision"),
        ) {
            Ok(context) => context,
            Err(error) => {
                return approval_response_error((*error).with_correlation(correlation_id));
            }
        };
        let Some(command) = request.command else {
            return approval_response_error(invalid_error("command_missing", correlation_id));
        };
        if let Err(error) =
            validate_command_metadata(request.client.as_ref(), command.metadata.as_ref())
        {
            return approval_response_error((*error).with_correlation(correlation_id));
        }
        match self.policy_port.execute(&command, &context.principal) {
            Ok(port_result) => {
                let (await_token, gateway_error) = self.issue_await_token(
                    &context.session,
                    port_result.source_revision,
                    port_result.await_target,
                    correlation_id,
                );
                DecideHarnessApprovalResponse {
                    await_token,
                    gateway_error,
                    sanitized_authority_result: Some(sanitize_policy_result(&port_result.result)),
                    policy_authority_result: None,
                }
            }
            Err(error) => approval_response_error(port_error(error, correlation_id)),
        }
    }

    pub fn execute_founder_verdict(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: ExecuteFounderVerdictRequest,
    ) -> ExecuteFounderVerdictResponse {
        let correlation_id =
            command_correlation_id(request.client.as_ref(), request.command.as_ref());
        let context = match self.authorize(
            peer,
            request.client.as_ref(),
            RPC_EXECUTE_VERDICT,
            verdict_oneof(request.command.as_ref()),
        ) {
            Ok(context) => context,
            Err(error) => {
                return ExecuteFounderVerdictResponse {
                    authority_result: None,
                    await_token: None,
                    gateway_error: Some((*error).with_correlation(correlation_id)),
                };
            }
        };
        let Some(command) = request.command else {
            return ExecuteFounderVerdictResponse {
                authority_result: None,
                await_token: None,
                gateway_error: Some(invalid_error("command_missing", correlation_id)),
            };
        };
        if let Err(error) =
            validate_command_metadata(request.client.as_ref(), verdict_metadata(&command))
        {
            return ExecuteFounderVerdictResponse {
                authority_result: None,
                await_token: None,
                gateway_error: Some((*error).with_correlation(correlation_id)),
            };
        }
        match self.verdict_port.execute(&command, &context.principal) {
            Ok(port_result) => ExecuteFounderVerdictResponse {
                authority_result: Some(port_result.result),
                // The frozen Local Read Model has no FounderVerdict view or
                // AwaitTarget. Returning no token is safer than inventing one.
                await_token: None,
                gateway_error: None,
            },
            Err(error) => ExecuteFounderVerdictResponse {
                authority_result: None,
                await_token: None,
                gateway_error: Some(port_error(error, correlation_id)),
            },
        }
    }

    pub fn execute_memory_mutation(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: ExecuteMemoryMutationRequest,
    ) -> ExecuteMemoryMutationResponse {
        let ExecuteMemoryMutationRequest { client, command } = request;
        let correlation_id = memory_command_correlation_id(client.as_ref(), command.as_ref());
        let context = match self.authorize(
            peer,
            client.as_ref(),
            RPC_EXECUTE_MEMORY,
            memory_oneof(command.as_ref()),
        ) {
            Ok(context) => context,
            Err(error) => {
                return ExecuteMemoryMutationResponse {
                    authority_result: None,
                    gateway_error: Some((*error).with_correlation(correlation_id)),
                };
            }
        };
        let Some(command) = command else {
            return ExecuteMemoryMutationResponse {
                authority_result: None,
                gateway_error: Some(invalid_error("command_missing", correlation_id)),
            };
        };
        if memory_metadata(&command).is_none() {
            return ExecuteMemoryMutationResponse {
                authority_result: None,
                gateway_error: Some(invalid_error("command_metadata_missing", correlation_id)),
            };
        }
        if memory_metadata(&command) != client.as_ref() {
            return ExecuteMemoryMutationResponse {
                authority_result: None,
                gateway_error: Some(invalid_error("command_metadata_mismatch", correlation_id)),
            };
        }
        match self.memory_port.execute(&command, &context.principal) {
            Ok(result) => ExecuteMemoryMutationResponse {
                authority_result: Some(result),
                gateway_error: None,
            },
            Err(error) => ExecuteMemoryMutationResponse {
                authority_result: None,
                gateway_error: Some(port_error(error, correlation_id)),
            },
        }
    }

    fn authorize(
        &self,
        peer: Option<&PeerConnectionInfo>,
        metadata: Option<&ClientRequestMetadata>,
        rpc: &str,
        oneof: Option<&str>,
    ) -> Result<CommandContext, Box<LocalApiError>> {
        let correlation_id = client_correlation_id(metadata);
        let peer = peer.ok_or_else(|| {
            Box::new(invalid_error(
                "peer_identity_missing",
                correlation_id.clone(),
            ))
        })?;
        let metadata = metadata.ok_or_else(|| {
            Box::new(invalid_error(
                "invalid_client_metadata",
                correlation_id.clone(),
            ))
        })?;
        validate_client_metadata(metadata).map_err(|_| {
            Box::new(invalid_error(
                "invalid_client_metadata",
                correlation_id.clone(),
            ))
        })?;
        let session = self
            .registry
            .authenticate(Some(metadata), peer)
            .map_err(|failure| Box::new(session_error(failure, correlation_id.clone())))?;
        let oneof = oneof
            .ok_or_else(|| Box::new(invalid_error("command_missing", correlation_id.clone())))?;
        let authorized = self
            .profiles
            .authorize_command(rpc, oneof, &session.permission_codes)
            .map_err(|failure| Box::new(profile_error(failure, correlation_id.clone())))?;
        if authorized.required_authority_principal_kinds.is_empty() {
            return Err(Box::new(critical_error(
                "authority_principal_kind_missing",
                correlation_id,
            )));
        }
        Ok(CommandContext {
            principal: CommandPrincipal {
                principal_id: session.authenticated_principal_id.clone(),
                required_authority_principal_kinds: authorized
                    .required_authority_principal_kinds
                    .clone(),
            },
            session,
            _authorized: authorized,
        })
    }

    fn authorize_rpc(
        &self,
        peer: Option<&PeerConnectionInfo>,
        metadata: Option<&ClientRequestMetadata>,
        rpc: &str,
    ) -> Result<WorkContext, Box<LocalApiError>> {
        let correlation_id = client_correlation_id(metadata);
        let peer = peer.ok_or_else(|| {
            Box::new(invalid_error(
                "peer_identity_missing",
                correlation_id.clone(),
            ))
        })?;
        let metadata = metadata.ok_or_else(|| {
            Box::new(invalid_error(
                "invalid_client_metadata",
                correlation_id.clone(),
            ))
        })?;
        validate_client_metadata(metadata).map_err(|_| {
            Box::new(invalid_error(
                "invalid_client_metadata",
                correlation_id.clone(),
            ))
        })?;
        let session = self
            .registry
            .authenticate(Some(metadata), peer)
            .map_err(|failure| Box::new(session_error(failure, correlation_id.clone())))?;
        self.profiles
            .authorize_rpc(rpc, &session.permission_codes)
            .map_err(|failure| Box::new(profile_error(failure, correlation_id.clone())))?;
        Ok(WorkContext {
            principal: CommandPrincipal {
                principal_id: session.authenticated_principal_id.clone(),
                // Preparation is compiler-only, while confirmation has one
                // fixed downstream write owner. The constraint is derived by
                // this gateway and cannot be supplied or widened by a client.
                required_authority_principal_kinds: if rpc == RPC_CONFIRM_WORK {
                    vec!["TaskAuthority.Founder".to_owned()]
                } else {
                    Vec::new()
                },
            },
            session,
        })
    }

    fn issue_await_token(
        &self,
        session: &AuthenticatedSession,
        source_revision: Option<SourceRevision>,
        target: Option<AwaitTarget>,
        correlation_id: String,
    ) -> (Option<ProjectionAwaitToken>, Option<LocalApiError>) {
        let (source_revision, target) = match (source_revision, target) {
            (None, None) => return (None, None),
            (Some(source_revision), Some(target)) => (source_revision, target),
            _ => {
                return (
                    None,
                    Some(api_error(
                        LocalApiErrorCode::IntegrityFailure,
                        "await_token_binding_incomplete",
                        false,
                        Some("RESTART_DAEMON"),
                        correlation_id,
                    )),
                );
            }
        };
        let scope = match ReadTokenScope::from_session(session) {
            Ok(scope) => scope,
            Err(_) => {
                return (
                    None,
                    Some(api_error(
                        LocalApiErrorCode::IntegrityFailure,
                        "await_token_scope_invalid",
                        false,
                        Some("RESTART_DAEMON"),
                        correlation_id,
                    )),
                );
            }
        };
        match self
            .token_codec
            .issue_await_token(&scope, source_revision, target)
        {
            Ok(token) => (Some(token), None),
            Err(_) => (
                None,
                Some(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "await_token_issue_failed",
                    false,
                    Some("RESTART_DAEMON"),
                    correlation_id,
                )),
            ),
        }
    }
}

struct CommandContext {
    principal: CommandPrincipal,
    session: AuthenticatedSession,
    _authorized: AuthorizedCommand,
}

struct WorkContext {
    principal: CommandPrincipal,
    session: AuthenticatedSession,
}

pub struct LocalCommandGatewayEndpoint {
    application: Arc<CommandGatewayApplication>,
}

impl LocalCommandGatewayEndpoint {
    #[must_use]
    pub fn new(application: Arc<CommandGatewayApplication>) -> Self {
        Self { application }
    }

    fn peer<T>(request: &Request<T>) -> Option<PeerConnectionInfo> {
        request.extensions().get::<PeerConnectionInfo>().cloned()
    }
}

#[tonic::async_trait]
impl LocalCommandGatewayService for LocalCommandGatewayEndpoint {
    async fn prepare_work(
        &self,
        request: Request<PrepareWorkRequest>,
    ) -> Result<Response<PrepareWorkResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .prepare_work(peer.as_ref(), request.into_inner()),
        ))
    }

    async fn confirm_work(
        &self,
        request: Request<ConfirmWorkRequest>,
    ) -> Result<Response<ConfirmWorkResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .confirm_work(peer.as_ref(), request.into_inner()),
        ))
    }

    async fn execute_task_command(
        &self,
        request: Request<ExecuteTaskCommandRequest>,
    ) -> Result<Response<ExecuteTaskCommandResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .execute_task_command(peer.as_ref(), request.into_inner()),
        ))
    }

    async fn decide_harness_approval(
        &self,
        request: Request<DecideHarnessApprovalRequest>,
    ) -> Result<Response<DecideHarnessApprovalResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(self.application.decide_harness_approval(
            peer.as_ref(),
            request.into_inner(),
        )))
    }

    async fn execute_founder_verdict(
        &self,
        request: Request<ExecuteFounderVerdictRequest>,
    ) -> Result<Response<ExecuteFounderVerdictResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(self.application.execute_founder_verdict(
            peer.as_ref(),
            request.into_inner(),
        )))
    }

    async fn execute_memory_mutation(
        &self,
        request: Request<ExecuteMemoryMutationRequest>,
    ) -> Result<Response<ExecuteMemoryMutationResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(self.application.execute_memory_mutation(
            peer.as_ref(),
            request.into_inner(),
        )))
    }

    async fn execute_context_mutation(
        &self,
        request: Request<ExecuteContextMutationRequest>,
    ) -> Result<Response<ExecuteContextMutationResponse>, Status> {
        let correlation_id = request
            .get_ref()
            .client
            .as_ref()
            .and_then(|metadata| metadata.correlation_id.clone())
            .unwrap_or_default();
        Ok(Response::new(ExecuteContextMutationResponse {
            outcome: Some(execute_context_mutation_response::Outcome::Error(
                api_error(
                    LocalApiErrorCode::AuthorityUnavailable,
                    "context_revoke_daemon_bridge_pending",
                    false,
                    Some("UPDATE_TO_R9A2_DAEMON_BRIDGE"),
                    correlation_id,
                ),
            )),
        }))
    }
}

fn validate_client_metadata(metadata: &ClientRequestMetadata) -> Result<(), ()> {
    if metadata.request_id.trim().is_empty()
        || metadata.request_id.len() > 256
        || metadata.request_id.chars().any(char::is_control)
    {
        return Err(());
    }
    if metadata.correlation_id.as_deref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) {
        return Err(());
    }
    Ok(())
}

fn validate_command_metadata(
    client: Option<&ClientRequestMetadata>,
    metadata: Option<&CommandMetadata>,
) -> Result<(), Box<LocalApiError>> {
    let Some(metadata) = metadata else {
        return Err(Box::new(invalid_error(
            "command_metadata_missing",
            String::new(),
        )));
    };
    if metadata.command_id.trim().is_empty()
        || metadata.idempotency_key.trim().is_empty()
        || metadata.idempotency_scope.trim().is_empty()
        || metadata.request_digest_sha256.trim().is_empty()
        || metadata.correlation_id.trim().is_empty()
    {
        return Err(Box::new(invalid_error(
            "command_metadata_incomplete",
            String::new(),
        )));
    }
    if let Some(client_correlation_id) = client.and_then(|value| value.correlation_id.as_deref())
        && client_correlation_id != metadata.correlation_id
    {
        return Err(Box::new(invalid_error(
            "correlation_id_mismatch",
            String::new(),
        )));
    }
    Ok(())
}

fn command_correlation_id<T>(client: Option<&ClientRequestMetadata>, command: Option<&T>) -> String
where
    T: CommandCorrelation,
{
    client
        .and_then(|value| value.correlation_id.clone())
        .or_else(|| command.and_then(CommandCorrelation::correlation_id))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

fn client_correlation_id(client: Option<&ClientRequestMetadata>) -> String {
    client
        .and_then(|value| value.correlation_id.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

trait CommandCorrelation {
    fn correlation_id(&self) -> Option<String>;
}

impl CommandCorrelation for TaskCommand {
    fn correlation_id(&self) -> Option<String> {
        task_metadata(self).map(|value| value.correlation_id.clone())
    }
}

impl CommandCorrelation for IssueHarnessApprovalDecisionCommand {
    fn correlation_id(&self) -> Option<String> {
        self.metadata
            .as_ref()
            .map(|value| value.correlation_id.clone())
    }
}

impl CommandCorrelation for VerdictCommand {
    fn correlation_id(&self) -> Option<String> {
        verdict_metadata(self).map(|value| value.correlation_id.clone())
    }
}

fn task_oneof(command: Option<&TaskCommand>) -> Option<&'static str> {
    Some(match command?.command.as_ref()? {
        task_command::Command::CreateTask(_) => "create_task",
        task_command::Command::ActivateTask(_) => "activate_task",
        task_command::Command::SubmitTaskEvidence(_) => "submit_task_evidence",
        task_command::Command::RecordTaskVerification(_) => "record_task_verification",
        task_command::Command::ApplyFounderVerdict(_) => "apply_founder_verdict",
        task_command::Command::ReviseTask(_) => "revise_task",
        task_command::Command::InterruptTask(_) => "interrupt_task",
        task_command::Command::HoldTask(_) => "hold_task",
        task_command::Command::ResumeTask(_) => "resume_task",
        task_command::Command::RequestTaskCancellation(_) => "request_task_cancellation",
        task_command::Command::RecordTaskCancellationOutcome(_) => {
            "record_task_cancellation_outcome"
        }
        task_command::Command::SupersedeTask(_) => "supersede_task",
        task_command::Command::ExpireTask(_) => "expire_task",
    })
}

fn task_metadata(command: &TaskCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        task_command::Command::CreateTask(value) => value.meta.as_ref(),
        task_command::Command::ActivateTask(value) => value.meta.as_ref(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_ref(),
        task_command::Command::RecordTaskVerification(value) => value.meta.as_ref(),
        task_command::Command::ApplyFounderVerdict(value) => value.meta.as_ref(),
        task_command::Command::ReviseTask(value) => value.meta.as_ref(),
        task_command::Command::InterruptTask(value) => value.meta.as_ref(),
        task_command::Command::HoldTask(value) => value.meta.as_ref(),
        task_command::Command::ResumeTask(value) => value.meta.as_ref(),
        task_command::Command::RequestTaskCancellation(value) => value.meta.as_ref(),
        task_command::Command::RecordTaskCancellationOutcome(value) => value.meta.as_ref(),
        task_command::Command::SupersedeTask(value) => value.meta.as_ref(),
        task_command::Command::ExpireTask(value) => value.meta.as_ref(),
    }
}

fn verdict_oneof(command: Option<&VerdictCommand>) -> Option<&'static str> {
    Some(match command?.command.as_ref()? {
        verdict_command::Command::IssueFounderVerdict(_) => "issue_founder_verdict",
        verdict_command::Command::ConsumeFounderVerdict(_) => "consume_founder_verdict",
        verdict_command::Command::RevokeFounderVerdict(_) => "revoke_founder_verdict",
        verdict_command::Command::ExpireFounderVerdict(_) => "expire_founder_verdict",
    })
}

fn verdict_metadata(command: &VerdictCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        verdict_command::Command::IssueFounderVerdict(value) => value.metadata.as_ref(),
        verdict_command::Command::ConsumeFounderVerdict(value) => value.metadata.as_ref(),
        verdict_command::Command::RevokeFounderVerdict(value) => value.metadata.as_ref(),
        verdict_command::Command::ExpireFounderVerdict(value) => value.metadata.as_ref(),
    }
}

fn memory_oneof(command: Option<&MemoryMutationCommand>) -> Option<&'static str> {
    Some(match command?.command.as_ref()? {
        egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::SubmitMemoryCandidate(_) => "submit_memory_candidate",
        egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::AcceptMemory(_) => "accept_memory",
        egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::RevokeMemory(_) => "revoke_memory",
    })
}

fn memory_metadata(command: &MemoryMutationCommand) -> Option<&ClientRequestMetadata> {
    match command.command.as_ref()? {
        egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::SubmitMemoryCandidate(value) => value.metadata.as_ref(),
        egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::AcceptMemory(value) => value.metadata.as_ref(),
        egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::RevokeMemory(value) => value.metadata.as_ref(),
    }
}

fn memory_command_correlation_id(
    client: Option<&ClientRequestMetadata>,
    command: Option<&MemoryMutationCommand>,
) -> String {
    client
        .and_then(|value| value.correlation_id.clone())
        .or_else(|| {
            command
                .and_then(memory_metadata)
                .and_then(|value| value.correlation_id.clone())
        })
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

fn sanitize_policy_result(result: &PolicyDecisionCommandResult) -> HarnessApprovalAuthorityResult {
    let record = result.decision_record.as_ref();
    let state = result.state.as_ref();
    HarnessApprovalAuthorityResult {
        committed: result.committed,
        replayed: result.replayed,
        authority_decision_ref: record
            .map(|value| value.authority_decision_ref.clone())
            .or_else(|| state.map(|value| value.authority_decision_ref.clone()))
            .unwrap_or_default(),
        decision: record.map_or(0, |value| value.decision),
        state: state.map_or(0, |value| value.state),
        state_revision: state.map_or(0, |value| value.revision),
        expires_at: record.and_then(|value| value.expires_at),
        error_code: result.error_code,
        safe_error_fingerprint: result.safe_error_fingerprint.clone(),
    }
}

fn session_error(failure: SessionAuthenticationFailure, correlation_id: String) -> LocalApiError {
    let (code, fingerprint, retryable, action) = match failure {
        SessionAuthenticationFailure::ContractMismatch => (
            LocalApiErrorCode::ContractIncompatible,
            "session_contract_mismatch",
            false,
            Some("RENEGOTIATE_CONTRACT"),
        ),
        SessionAuthenticationFailure::Expired => (
            LocalApiErrorCode::SessionExpired,
            "session_expired",
            true,
            Some("REOPEN_SESSION"),
        ),
        SessionAuthenticationFailure::PolicyUnavailable => (
            LocalApiErrorCode::AuthorityUnavailable,
            "authorization_policy_unavailable",
            true,
            Some("RETRY"),
        ),
        SessionAuthenticationFailure::IntegrityFailure => (
            LocalApiErrorCode::IntegrityFailure,
            "session_registry_integrity_failure",
            false,
            Some("RESTART_DAEMON"),
        ),
        SessionAuthenticationFailure::Revoked | SessionAuthenticationFailure::PolicyDrift => (
            LocalApiErrorCode::PermissionDenied,
            "session_authorization_changed",
            false,
            Some("REOPEN_SESSION"),
        ),
        SessionAuthenticationFailure::MissingMetadata
        | SessionAuthenticationFailure::NotFound
        | SessionAuthenticationFailure::PeerMismatch
        | SessionAuthenticationFailure::ClientBindingMismatch => (
            LocalApiErrorCode::Unauthenticated,
            "session_authentication_failed",
            false,
            Some("REOPEN_SESSION"),
        ),
    };
    api_error(code, fingerprint, retryable, action, correlation_id)
}

fn profile_error(failure: ContractProfileError, correlation_id: String) -> LocalApiError {
    match failure {
        ContractProfileError::PermissionDenied(_)
        | ContractProfileError::SystemOnlyCommand { .. } => api_error(
            LocalApiErrorCode::PermissionDenied,
            "command_permission_denied",
            false,
            None,
            correlation_id,
        ),
        _ => critical_error("authorization_profile_semantics_unknown", correlation_id),
    }
}

fn port_error(failure: CommandPortFailure, correlation_id: String) -> LocalApiError {
    match failure {
        CommandPortFailure::Unavailable => api_error(
            LocalApiErrorCode::AuthorityUnavailable,
            "authority_unavailable",
            true,
            Some("RETRY"),
            correlation_id,
        ),
        CommandPortFailure::DeliveryUnknown => api_error(
            LocalApiErrorCode::AuthorityUnavailable,
            "authority_delivery_unknown",
            false,
            Some("RECONCILE_BEFORE_RETRY"),
            correlation_id,
        ),
        CommandPortFailure::IntegrityFailure => api_error(
            LocalApiErrorCode::IntegrityFailure,
            "authority_integrity_failure",
            false,
            Some("RESTART_DAEMON"),
            correlation_id,
        ),
    }
}

fn invalid_error(fingerprint: &'static str, correlation_id: String) -> LocalApiError {
    api_error(
        LocalApiErrorCode::InvalidArgument,
        fingerprint,
        false,
        None,
        correlation_id,
    )
}

fn critical_error(fingerprint: &'static str, correlation_id: String) -> LocalApiError {
    api_error(
        LocalApiErrorCode::UnknownCriticalSemantics,
        fingerprint,
        false,
        Some("UPDATE_OR_REPAIR"),
        correlation_id,
    )
}

fn api_error(
    code: LocalApiErrorCode,
    fingerprint: &'static str,
    retryable: bool,
    action: Option<&'static str>,
    correlation_id: String,
) -> LocalApiError {
    LocalApiError {
        code: code as i32,
        safe_fingerprint: fingerprint.to_owned(),
        retryable,
        required_action_code: action.map(str::to_owned),
        current_position: None,
        correlation_id,
    }
}

trait CorrelatedError {
    fn with_correlation(self, correlation_id: String) -> LocalApiError;
}

impl CorrelatedError for LocalApiError {
    fn with_correlation(mut self, correlation_id: String) -> LocalApiError {
        self.correlation_id = correlation_id;
        self
    }
}

#[allow(deprecated)]
fn approval_response_error(error: LocalApiError) -> DecideHarnessApprovalResponse {
    DecideHarnessApprovalResponse {
        await_token: None,
        gateway_error: Some(error),
        policy_authority_result: None,
        sanitized_authority_result: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_result_sanitization_excludes_authority_proof_and_request_binding() {
        let result = PolicyDecisionCommandResult {
            committed: true,
            replayed: false,
            decision_record: None,
            state: None,
            consumption_receipt: None,
            event: None,
            error_code: 0,
            safe_error_fingerprint: Some("ok".to_owned()),
        };
        let sanitized = sanitize_policy_result(&result);
        assert!(sanitized.authority_decision_ref.is_empty());
        assert_eq!(sanitized.safe_error_fingerprint.as_deref(), Some("ok"));
    }

    #[test]
    fn command_metadata_correlation_must_match_client_metadata() {
        let client = ClientRequestMetadata {
            request_id: "request-1".to_owned(),
            correlation_id: Some("client-correlation".to_owned()),
            ..Default::default()
        };
        let metadata = CommandMetadata {
            command_id: "command-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            idempotency_scope: "scope-1".to_owned(),
            request_digest_sha256: "digest".to_owned(),
            correlation_id: "command-correlation".to_owned(),
            ..Default::default()
        };
        let error = validate_command_metadata(Some(&client), Some(&metadata)).unwrap_err();
        assert_eq!(error.safe_fingerprint, "correlation_id_mismatch");
    }

    #[test]
    fn memory_command_metadata_must_be_the_same_client_binding() {
        let client = ClientRequestMetadata {
            request_id: "request-1".to_owned(),
            client_instance_id: "cli-1".to_owned(),
            session_id: "session-1".to_owned(),
            correlation_id: Some("correlation-1".to_owned()),
            ..Default::default()
        };
        let command = MemoryMutationCommand {
            command: Some(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::memory_mutation_command::Command::SubmitMemoryCandidate(
                    egopulse_domain_contracts::v01::egopulse::localapi::v1::SubmitMemoryCandidateCommand {
                        metadata: Some(ClientRequestMetadata {
                            correlation_id: Some("other-correlation".to_owned()),
                            ..client.clone()
                        }),
                        ..Default::default()
                    },
                ),
            ),
        };
        assert_ne!(memory_metadata(&command), Some(&client));
    }
}
