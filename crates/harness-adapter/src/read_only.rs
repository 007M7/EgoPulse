use crate::{DriverError, NativeHarnessFuture};
use std::{path::PathBuf, time::Duration};

/// Fresh, tools-disabled cognition. It cannot create a Task or mutate an Authority.
#[derive(Clone, Debug)]
pub struct ReadOnlyTurnRequest {
    pub execution_id: String,
    pub working_directory: PathBuf,
    pub model: String,
    pub prompt: String,
    pub output_schema: serde_json::Value,
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyTurnStatus {
    Completed,
    Interrupted,
    Failed,
}
#[derive(Clone, Debug)]
pub struct ReadOnlyTurnOutcome {
    pub model: String,
    pub terminal_status: ReadOnlyTurnStatus,
    pub assistant_output: Vec<u8>,
}
/// A separate cognition capability. Existing native dispatch admission conveys
/// no additional tools, context, fallback or persisted authority rights here.
pub trait ReadOnlyTurnDriver: Send {
    fn run_bounded_read_only_turn<'a>(
        &'a mut self,
        request: ReadOnlyTurnRequest,
    ) -> NativeHarnessFuture<'a, Result<ReadOnlyTurnOutcome, DriverError>>;
}
