use std::{collections::BTreeSet, time::SystemTime};

use egopulse_client_kernel::{
    HarnessAssistantMessage, HarnessContentStreamTracker, KernelError, StreamApply,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    HarnessContentBaselinePage, HarnessContentPosition, HarnessContentRecordView,
    HarnessContentResetReason, HarnessContentStreamFrame, ListHarnessContentRequest,
    ListHarnessContentResponse, WatchHarnessContentRequest, harness_content_stream_frame,
    list_harness_content_response,
};
use thiserror::Error;
use uuid::Uuid;

use crate::ClientAttachment;

const LIST_HARNESS_CONTENT_RPC: &str = "LocalReadModelService/ListHarnessContent";
const WATCH_HARNESS_CONTENT_RPC: &str = "LocalReadModelService/WatchHarnessContent";
const BASELINE_PAGE_SIZE: u32 = 256;
const BASELINE_MAX_PAGES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessContentFilter {
    task_id: String,
    attempt_ids: Vec<String>,
}

impl HarnessContentFilter {
    pub fn new(
        task_id: impl Into<String>,
        attempt_ids: Vec<String>,
    ) -> Result<Self, ClientHarnessContentError> {
        let task_id = task_id.into();
        if !valid_identifier(&task_id) {
            return Err(ClientHarnessContentError::InvalidInput("task_id"));
        }
        let mut canonical = attempt_ids;
        if canonical.iter().any(|value| !valid_identifier(value)) {
            return Err(ClientHarnessContentError::InvalidInput("attempt_ids"));
        }
        canonical.sort();
        if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ClientHarnessContentError::InvalidInput(
                "attempt_ids contain a duplicate",
            ));
        }
        Ok(Self {
            task_id,
            attempt_ids: canonical,
        })
    }

    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    #[must_use]
    pub fn attempt_ids(&self) -> &[String] {
        &self.attempt_ids
    }

    fn allows(&self, record: &HarnessContentRecordView) -> bool {
        record.task_id == self.task_id
            && (self.attempt_ids.is_empty()
                || self.attempt_ids.binary_search(&record.attempt_id).is_ok())
    }
}

#[derive(Debug, Error)]
pub enum ClientHarnessContentError {
    #[error("client kernel rejected governed Harness content: {0}")]
    Kernel(#[from] KernelError),
    #[error("governed Harness content input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("local API governed Harness content transport failed: {0}")]
    Transport(String),
    #[error("local API rejected governed Harness content: {0:?}")]
    Api(Box<egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiError>),
    #[error("governed Harness content protocol integrity failed: {0}")]
    Protocol(&'static str),
    #[error("governed Harness content baseline exceeded its bounded page limit")]
    BaselineLimitExceeded,
    #[error("governed Harness content watch ended unexpectedly")]
    UnexpectedEof,
    #[error("governed Harness content requires a new baseline")]
    ResetBarrier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessContentUpdateKind {
    Records,
    Heartbeat,
    ResetRequired,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HarnessContentUpdate {
    pub disposition: StreamApply,
    pub kind: HarnessContentUpdateKind,
    pub position: HarnessContentPosition,
    pub records: Vec<HarnessContentRecordView>,
    pub changed_messages: Vec<HarnessAssistantMessage>,
    pub reset_reason: Option<HarnessContentResetReason>,
}

/// Pure, bounded state shared by the attached network session and all client
/// surfaces. It accepts only Local API post-disclosure DTOs.
#[derive(Debug)]
pub struct HarnessContentDriver {
    filter: HarnessContentFilter,
    tracker: HarnessContentStreamTracker,
    records: Vec<HarnessContentRecordView>,
}

impl HarnessContentDriver {
    #[must_use]
    pub fn new(filter: HarnessContentFilter) -> Self {
        Self {
            filter,
            tracker: HarnessContentStreamTracker::default(),
            records: Vec::new(),
        }
    }

    #[must_use]
    pub fn filter(&self) -> &HarnessContentFilter {
        &self.filter
    }

    #[must_use]
    pub fn position(&self) -> Option<&HarnessContentPosition> {
        self.tracker.last_position()
    }

    #[must_use]
    pub const fn baseline_complete(&self) -> bool {
        self.tracker.baseline_complete()
    }

    #[must_use]
    pub const fn refetch_required(&self) -> bool {
        self.tracker.refetch_required()
    }

    #[must_use]
    pub fn records(&self) -> &[HarnessContentRecordView] {
        &self.records
    }

    #[must_use]
    pub fn assistant_messages(&self) -> Vec<&HarnessAssistantMessage> {
        self.tracker.assistant_messages()
    }

    pub fn apply_baseline_page(
        &mut self,
        page: &HarnessContentBaselinePage,
    ) -> Result<(), ClientHarnessContentError> {
        if page
            .records
            .iter()
            .any(|record| !self.filter.allows(record))
        {
            return Err(ClientHarnessContentError::Protocol(
                "baseline record escaped the requested Task/Attempt scope",
            ));
        }
        self.tracker.apply_baseline_page(page)?;
        self.records.extend(page.records.iter().cloned());
        Ok(())
    }

    pub fn apply_stream_frame(
        &mut self,
        frame: &HarnessContentStreamFrame,
    ) -> Result<HarnessContentUpdate, ClientHarnessContentError> {
        if self.refetch_required() {
            return Err(ClientHarnessContentError::ResetBarrier);
        }
        let (kind, frame_records, reset_reason) = match frame.payload.as_ref() {
            Some(harness_content_stream_frame::Payload::Records(value)) => {
                if value
                    .records
                    .iter()
                    .any(|record| !self.filter.allows(record))
                {
                    return Err(ClientHarnessContentError::Protocol(
                        "watch record escaped the requested Task/Attempt scope",
                    ));
                }
                (
                    HarnessContentUpdateKind::Records,
                    value.records.clone(),
                    None,
                )
            }
            Some(harness_content_stream_frame::Payload::Heartbeat(_)) => {
                (HarnessContentUpdateKind::Heartbeat, Vec::new(), None)
            }
            Some(harness_content_stream_frame::Payload::ResetRequired(value)) => (
                HarnessContentUpdateKind::ResetRequired,
                Vec::new(),
                HarnessContentResetReason::try_from(value.reason).ok(),
            ),
            None => return Err(KernelError::IncompleteStreamFrame.into()),
        };
        let applied = self.tracker.apply_stream_frame(frame)?;
        let records = if applied.disposition == StreamApply::Applied {
            self.records.extend(frame_records.iter().cloned());
            frame_records
        } else {
            Vec::new()
        };
        if applied.disposition == StreamApply::ResetRequired {
            self.records.clear();
        }
        let changed_messages = applied
            .changed_message_ids
            .iter()
            .map(|message_id| {
                self.tracker.assistant_message(message_id).cloned().ok_or(
                    ClientHarnessContentError::Protocol(
                        "changed assistant message is missing after apply",
                    ),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let position = frame
            .position
            .clone()
            .ok_or(KernelError::StreamPositionInvalid)?;
        Ok(HarnessContentUpdate {
            disposition: applied.disposition,
            kind,
            position,
            records,
            changed_messages,
            reset_reason,
        })
    }
}

pub struct HarnessContentSession {
    stream: tonic::Streaming<HarnessContentStreamFrame>,
    driver: HarnessContentDriver,
}

impl HarnessContentSession {
    #[must_use]
    pub fn filter(&self) -> &HarnessContentFilter {
        self.driver.filter()
    }

    #[must_use]
    pub fn position(&self) -> &HarnessContentPosition {
        self.driver
            .position()
            .expect("network session is created only after a complete baseline")
    }

    #[must_use]
    pub fn records(&self) -> &[HarnessContentRecordView] {
        self.driver.records()
    }

    #[must_use]
    pub fn assistant_messages(&self) -> Vec<&HarnessAssistantMessage> {
        self.driver.assistant_messages()
    }

    pub async fn next_update(&mut self) -> Result<HarnessContentUpdate, ClientHarnessContentError> {
        if self.driver.refetch_required() {
            return Err(ClientHarnessContentError::ResetBarrier);
        }
        let frame = self
            .stream
            .message()
            .await
            .map_err(|error| ClientHarnessContentError::Transport(error.to_string()))?
            .ok_or(ClientHarnessContentError::UnexpectedEof)?;
        self.driver.apply_stream_frame(&frame)
    }
}

impl ClientAttachment {
    /// Reads one fixed content baseline and opens its exactly paired live
    /// watch. Surfaces cannot accidentally combine positions from another
    /// domain or baseline generation.
    pub async fn open_harness_content_session(
        &self,
        filter: HarnessContentFilter,
    ) -> Result<HarnessContentSession, ClientHarnessContentError> {
        self.require_rpc(LIST_HARNESS_CONTENT_RPC)?;
        let mut driver = HarnessContentDriver::new(filter);
        let mut client = self.connection.read_model_service();
        let mut cursor = None;
        let mut snapshot_position = None;
        let mut seen_cursors = BTreeSet::new();

        for page_index in 0..BASELINE_MAX_PAGES {
            let metadata = self.kernel.request_metadata(
                Uuid::now_v7().to_string(),
                None,
                SystemTime::now(),
            )?;
            let response = client
                .list_harness_content(ListHarnessContentRequest {
                    client: Some(metadata),
                    task_id: driver.filter.task_id.clone(),
                    attempt_ids: driver.filter.attempt_ids.clone(),
                    page_size: BASELINE_PAGE_SIZE,
                    page_cursor: cursor.clone(),
                    snapshot_position: snapshot_position.clone(),
                })
                .await
                .map_err(|error| ClientHarnessContentError::Transport(error.to_string()))?
                .into_inner();
            let page = response_page(response)?;
            if page_index == 0 {
                snapshot_position = page.snapshot_position.clone();
            }
            driver.apply_baseline_page(&page)?;
            if !page.has_more {
                break;
            }
            let next = page
                .next_page_cursor
                .ok_or(ClientHarnessContentError::Protocol(
                    "baseline continuation cursor is missing",
                ))?;
            if !seen_cursors.insert(next.clone()) {
                return Err(ClientHarnessContentError::Protocol(
                    "baseline continuation cursor looped",
                ));
            }
            cursor = Some(next);
        }
        if !driver.baseline_complete() {
            return Err(ClientHarnessContentError::BaselineLimitExceeded);
        }

        self.require_rpc(WATCH_HARNESS_CONTENT_RPC)?;
        let resume_after =
            driver
                .position()
                .cloned()
                .ok_or(ClientHarnessContentError::Protocol(
                    "complete baseline position is missing",
                ))?;
        let metadata =
            self.kernel
                .request_metadata(Uuid::now_v7().to_string(), None, SystemTime::now())?;
        let stream = client
            .watch_harness_content(WatchHarnessContentRequest {
                client: Some(metadata),
                task_id: driver.filter.task_id.clone(),
                attempt_ids: driver.filter.attempt_ids.clone(),
                resume_after: Some(resume_after),
            })
            .await
            .map_err(|error| ClientHarnessContentError::Transport(error.to_string()))?
            .into_inner();
        Ok(HarnessContentSession { stream, driver })
    }
}

fn response_page(
    response: ListHarnessContentResponse,
) -> Result<HarnessContentBaselinePage, ClientHarnessContentError> {
    match response.outcome {
        Some(list_harness_content_response::Outcome::Page(page)) => Ok(page),
        Some(list_harness_content_response::Outcome::Error(error)) => {
            Err(ClientHarnessContentError::Api(Box::new(error)))
        }
        None => Err(ClientHarnessContentError::Protocol(
            "baseline response outcome is missing",
        )),
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}
