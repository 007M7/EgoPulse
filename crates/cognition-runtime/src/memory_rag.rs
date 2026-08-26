//! Rust-owned Memory/RAG Worker boundary.
//!
//! The authority materializes an accepted snapshot, this module serializes it
//! once into the approved Protobuf request, and the supervised Python Worker
//! returns only ranked references. Rust validates the response before any
//! context compiler may consume it.

use crate::memory_authority::{AcceptedMemorySnapshot, MemoryState};
use egopulse_domain_contracts::memory::{
    MEMORY_ALGORITHM_ID, MemoryResponseError, validate_retrieval_input, validate_retrieval_response,
};
use egopulse_domain_contracts::v01::egopulse::memory::v1::{
    AcceptedMemoryInput, MemoryRetrievalRequest, RetrievalRequest, RetrievalResponse,
};
use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, SupervisedProcessSpec, run_governed_framed_process,
};
use prost::Message;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct MemoryRagWorker {
    spec: SupervisedProcessSpec,
    budget: GovernedProcessBudget,
}

impl MemoryRagWorker {
    #[must_use]
    pub const fn new(spec: SupervisedProcessSpec, budget: GovernedProcessBudget) -> Self {
        Self { spec, budget }
    }

    pub async fn retrieve(
        &self,
        snapshot: &AcceptedMemorySnapshot,
        query: &str,
        max_results: u32,
        min_score: f64,
    ) -> Result<RetrievalResponse, MemoryRagWorkerFailure> {
        let request = RetrievalRequest {
            query: query.to_owned(),
            scope_ref: snapshot.scope_ref.clone(),
            snapshot_sha256: snapshot.snapshot_sha256.clone(),
            max_results,
            min_score,
            algorithm_profile: MEMORY_ALGORITHM_ID.to_owned(),
        };
        let mut accepted_records = Vec::with_capacity(snapshot.records.len());
        for record in &snapshot.records {
            if !matches!(record.state, MemoryState::Accepted) {
                return Err(MemoryRagWorkerFailure::NonAcceptedSnapshotRecord);
            }
            accepted_records.push(AcceptedMemoryInput {
                memory_id: record.memory_id.clone(),
                content: record.content.clone(),
                content_sha256: record.content_sha256.clone(),
                source_ref: record.source_ref.clone(),
                scope_ref: record.scope_ref.clone(),
                revision: record.revision,
            });
        }
        validate_retrieval_input(&request, &accepted_records)?;

        let framed_request = MemoryRetrievalRequest {
            retrieval: Some(request.clone()),
            accepted_records,
        };
        let receipt =
            run_governed_framed_process(&self.spec, &framed_request.encode_to_vec(), self.budget)
                .await?;
        let response = RetrievalResponse::decode(receipt.stdout.as_slice())?;
        validate_retrieval_response(&request, &framed_request.accepted_records, &response)?;
        Ok(response)
    }
}

#[derive(Debug, Error)]
pub enum MemoryRagWorkerFailure {
    #[error("accepted snapshot contains a non-accepted record")]
    NonAcceptedSnapshotRecord,
    #[error("Memory/RAG input or response violated the contract: {0}")]
    Contract(#[from] MemoryResponseError),
    #[error("Memory/RAG Worker process failed: {0}")]
    Process(#[from] GovernedProcessError),
    #[error("Memory/RAG Worker response was not valid Protobuf")]
    Decode(#[from] prost::DecodeError),
}
