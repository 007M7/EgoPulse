use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_cognition_runtime::{
    memory_authority::{AcceptedMemorySnapshot, MemoryAuthority, MemoryAuthorityFailure},
    memory_rag::{MemoryRagWorker, MemoryRagWorkerFailure},
};
use egopulse_domain_contracts::{
    memory::MemoryResponseError, v01::egopulse::memory::v1::RetrievalResponse,
};
use egopulse_local_api::cognition_gateway::{
    MemoryRetrievalAuditEvent, MemoryRetrievalAuditSink, MemoryRetrievalInput, MemoryRetrievalPort,
    MemoryRetrievalPortError,
};
use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, SupervisedProcessSpec,
};
use tokio::sync::Semaphore;

#[derive(Clone, Debug)]
pub struct MemoryRetrievalCompositionConfig {
    pub worker_executable: PathBuf,
    pub worker_arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub inherited_environment: BTreeSet<String>,
    pub environment_overrides: BTreeMap<String, String>,
    pub timeout: Duration,
    pub output_limit_bytes: u64,
    pub principal_scope_allowlist: BTreeMap<String, BTreeSet<String>>,
}

impl MemoryRetrievalCompositionConfig {
    pub fn validate(&self) -> Result<(), MemoryRetrievalConfigurationError> {
        if !self.worker_executable.is_absolute()
            || self.worker_executable.as_os_str().is_empty()
            || !self.working_directory.is_absolute()
            || self.working_directory.as_os_str().is_empty()
        {
            return Err(MemoryRetrievalConfigurationError::InvalidWorkerPath);
        }
        if self.timeout < Duration::from_millis(10) || self.timeout > Duration::from_secs(120) {
            return Err(MemoryRetrievalConfigurationError::InvalidBudget);
        }
        if !(1..=16 * 1024 * 1024).contains(&self.output_limit_bytes) {
            return Err(MemoryRetrievalConfigurationError::InvalidBudget);
        }
        if self.principal_scope_allowlist.is_empty()
            || self
                .principal_scope_allowlist
                .iter()
                .any(|(principal, scopes)| {
                    principal.trim().is_empty()
                        || scopes.is_empty()
                        || scopes.iter().any(|scope| scope.trim().is_empty())
                })
        {
            return Err(MemoryRetrievalConfigurationError::InvalidScopeAllowlist);
        }
        if self
            .inherited_environment
            .iter()
            .any(|name| name.trim().is_empty() || name.contains('='))
            || self.environment_overrides.iter().any(|(name, value)| {
                name.trim().is_empty() || name.contains('=') || value.contains('\0')
            })
        {
            return Err(MemoryRetrievalConfigurationError::InvalidEnvironment);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MemoryRetrievalConfigurationError {
    #[error("Memory retrieval Worker paths must be absolute")]
    InvalidWorkerPath,
    #[error("Memory retrieval Worker budget is invalid")]
    InvalidBudget,
    #[error("Memory retrieval principal-to-scope allowlist is invalid")]
    InvalidScopeAllowlist,
    #[error("Memory retrieval Worker environment is invalid")]
    InvalidEnvironment,
}

pub struct ConfiguredMemoryRetrievalPort {
    authority: Arc<Mutex<MemoryAuthority>>,
    worker: MemoryRagWorker,
    principal_scope_allowlist: BTreeMap<String, BTreeSet<String>>,
    active: Semaphore,
}

impl ConfiguredMemoryRetrievalPort {
    pub fn new(
        authority: Arc<Mutex<MemoryAuthority>>,
        config: MemoryRetrievalCompositionConfig,
    ) -> Result<Self, MemoryRetrievalConfigurationError> {
        config.validate()?;
        let spec = SupervisedProcessSpec {
            executable: config.worker_executable,
            arguments: config.worker_arguments,
            working_directory: config.working_directory,
            clear_environment: true,
            inherited_environment: config.inherited_environment.into_iter().collect(),
            environment_overrides: config.environment_overrides.into_iter().collect(),
        };
        let worker = MemoryRagWorker::new(
            spec,
            GovernedProcessBudget {
                timeout: config.timeout,
                output_limit_bytes: config.output_limit_bytes,
            },
        );
        Ok(Self {
            authority,
            worker,
            principal_scope_allowlist: config.principal_scope_allowlist,
            active: Semaphore::new(1),
        })
    }

    fn scope_allowed(&self, principal_id: &str, scope_ref: &str) -> bool {
        self.principal_scope_allowlist
            .get(principal_id)
            .is_some_and(|scopes| scopes.contains(scope_ref))
    }

    fn accepted_snapshot(
        &self,
        principal_id: &str,
        scope_ref: &str,
    ) -> Result<AcceptedMemorySnapshot, MemoryRetrievalPortError> {
        if !self.scope_allowed(principal_id, scope_ref) {
            return Err(MemoryRetrievalPortError::ScopeDenied);
        }
        self.authority
            .lock()
            .map_err(|_| MemoryRetrievalPortError::AuthorityUnavailable)?
            .accepted_snapshot(scope_ref)
            .map_err(map_authority_failure)
    }

    async fn retrieve_governed(
        &self,
        request: MemoryRetrievalInput,
    ) -> Result<GovernedWorkMemoryRetrieval, MemoryRetrievalPortError> {
        if !self.scope_allowed(&request.authenticated_principal_id, &request.scope_ref) {
            return Err(MemoryRetrievalPortError::ScopeDenied);
        }
        let _permit = self
            .active
            .try_acquire()
            .map_err(|_| MemoryRetrievalPortError::ResourceExhausted)?;

        let authority = Arc::clone(&self.authority);
        let scope_ref = request.scope_ref.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            authority
                .lock()
                .map_err(|_| MemoryAuthorityFailure::Storage)?
                .accepted_snapshot(&scope_ref)
        })
        .await
        .map_err(|_| MemoryRetrievalPortError::AuthorityUnavailable)?
        .map_err(map_authority_failure)?;

        let response = self
            .worker
            .retrieve(
                &snapshot,
                &request.query,
                request.max_results,
                request.min_score,
            )
            .await
            .map_err(map_worker_failure)?;
        Ok(GovernedWorkMemoryRetrieval { snapshot, response })
    }
}

/// Internal preparation result. The Worker response remains reference-only;
/// the exact Authority snapshot is retained so the Context compiler can
/// resolve and bind selected bytes without trusting Worker-owned content.
#[derive(Clone, Debug)]
pub struct GovernedWorkMemoryRetrieval {
    pub snapshot: AcceptedMemorySnapshot,
    pub response: RetrievalResponse,
}

#[tonic::async_trait]
pub trait WorkMemoryRetrievalPort: Send + Sync + 'static {
    async fn retrieve_for_work(
        &self,
        request: MemoryRetrievalInput,
    ) -> Result<GovernedWorkMemoryRetrieval, MemoryRetrievalPortError>;

    fn revalidate_accepted_snapshot(
        &self,
        principal_id: &str,
        scope_ref: &str,
    ) -> Result<AcceptedMemorySnapshot, MemoryRetrievalPortError>;
}

#[tonic::async_trait]
impl MemoryRetrievalPort for ConfiguredMemoryRetrievalPort {
    async fn retrieve(
        &self,
        request: MemoryRetrievalInput,
    ) -> Result<RetrievalResponse, MemoryRetrievalPortError> {
        self.retrieve_governed(request)
            .await
            .map(|retrieval| retrieval.response)
    }
}

#[tonic::async_trait]
impl WorkMemoryRetrievalPort for ConfiguredMemoryRetrievalPort {
    async fn retrieve_for_work(
        &self,
        request: MemoryRetrievalInput,
    ) -> Result<GovernedWorkMemoryRetrieval, MemoryRetrievalPortError> {
        self.retrieve_governed(request).await
    }

    fn revalidate_accepted_snapshot(
        &self,
        principal_id: &str,
        scope_ref: &str,
    ) -> Result<AcceptedMemorySnapshot, MemoryRetrievalPortError> {
        self.accepted_snapshot(principal_id, scope_ref)
    }
}

#[derive(Default)]
pub struct FailClosedMemoryRetrievalPort;

#[tonic::async_trait]
impl MemoryRetrievalPort for FailClosedMemoryRetrievalPort {
    async fn retrieve(
        &self,
        _request: MemoryRetrievalInput,
    ) -> Result<RetrievalResponse, MemoryRetrievalPortError> {
        Err(MemoryRetrievalPortError::WorkerUnavailable)
    }
}

#[tonic::async_trait]
impl WorkMemoryRetrievalPort for FailClosedMemoryRetrievalPort {
    async fn retrieve_for_work(
        &self,
        _request: MemoryRetrievalInput,
    ) -> Result<GovernedWorkMemoryRetrieval, MemoryRetrievalPortError> {
        Err(MemoryRetrievalPortError::WorkerUnavailable)
    }

    fn revalidate_accepted_snapshot(
        &self,
        _principal_id: &str,
        _scope_ref: &str,
    ) -> Result<AcceptedMemorySnapshot, MemoryRetrievalPortError> {
        Err(MemoryRetrievalPortError::WorkerUnavailable)
    }
}

#[derive(Default)]
pub struct TracingMemoryRetrievalAuditSink;

impl MemoryRetrievalAuditSink for TracingMemoryRetrievalAuditSink {
    fn record(&self, event: MemoryRetrievalAuditEvent) {
        tracing::info!(
            target: "egopulse.memory_retrieval_audit",
            principal_id = %event.authenticated_principal_id,
            request_id = %event.request_id,
            correlation_id = %event.correlation_id,
            scope_ref = %event.scope_ref,
            query_sha256 = %event.query_sha256,
            snapshot_sha256 = event.snapshot_sha256.as_deref().unwrap_or(""),
            result_count = event.result_count.unwrap_or(0),
            algorithm_id = event.algorithm_id.as_deref().unwrap_or(""),
            evidence_ref = event.evidence_ref.as_deref().unwrap_or(""),
            outcome = event.safe_outcome_code,
            "governed Memory retrieval"
        );
    }
}

fn map_authority_failure(failure: MemoryAuthorityFailure) -> MemoryRetrievalPortError {
    match failure {
        MemoryAuthorityFailure::InvalidArgument(_) => MemoryRetrievalPortError::InvalidArgument,
        MemoryAuthorityFailure::Unauthorized => MemoryRetrievalPortError::ScopeDenied,
        MemoryAuthorityFailure::Storage => MemoryRetrievalPortError::AuthorityUnavailable,
        MemoryAuthorityFailure::NotFound
        | MemoryAuthorityFailure::StateConflict
        | MemoryAuthorityFailure::IdempotencyConflict
        | MemoryAuthorityFailure::Clock => MemoryRetrievalPortError::IntegrityFailure,
    }
}

fn map_worker_failure(failure: MemoryRagWorkerFailure) -> MemoryRetrievalPortError {
    match failure {
        MemoryRagWorkerFailure::Process(GovernedProcessError::Timeout) => {
            MemoryRetrievalPortError::DeadlineExceeded
        }
        MemoryRagWorkerFailure::Process(
            GovernedProcessError::InvalidSpecification
            | GovernedProcessError::Spawn
            | GovernedProcessError::InputDelivery
            | GovernedProcessError::Crashed
            | GovernedProcessError::Io,
        ) => MemoryRetrievalPortError::WorkerUnavailable,
        MemoryRagWorkerFailure::Contract(
            MemoryResponseError::MissingQuery
            | MemoryResponseError::MissingScope
            | MemoryResponseError::InvalidMaxResults
            | MemoryResponseError::InvalidMinScore
            | MemoryResponseError::QueryTooLarge,
        ) => MemoryRetrievalPortError::InvalidArgument,
        MemoryRagWorkerFailure::NonAcceptedSnapshotRecord
        | MemoryRagWorkerFailure::Contract(_)
        | MemoryRagWorkerFailure::Process(
            GovernedProcessError::OutputLimit | GovernedProcessError::Protocol,
        )
        | MemoryRagWorkerFailure::Decode(_) => MemoryRetrievalPortError::IntegrityFailure,
    }
}
