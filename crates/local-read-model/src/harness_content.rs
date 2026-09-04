//! Independent R9C Harness-content projection domain.
//!
//! This module consumes only Adapter-owned safe projection events. It has no
//! route to native evidence or Authority stores. Artifact visibility is an
//! already-verified access mask supplied by the Local API; this module never
//! derives permissions from a principal.

use std::collections::BTreeSet;

use egopulse_domain_contracts::{
    profiles::{
        ContractProfiles, HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID,
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256, HARNESS_CONTENT_DISCLOSURE_PROFILE_ID,
    },
    v01::egopulse::{
        common::v1::ContractReference,
        harness::v1::{
            ContentMutationOperation, HarnessContentMarkerKind, HarnessContentSafetyFlag,
            LifecycleKind, SafeHarnessContentProjectionEvent, SafeHarnessContentRecord,
            SideEffectCertainty, safe_harness_content_projection_event,
            safe_harness_content_record,
        },
        localapi::v1::{
            HarnessApprovalRequiredContentView, HarnessArtifactAvailableRedactedView,
            HarnessArtifactIdentityView, HarnessArtifactRelationView, HarnessAssistantTextView,
            HarnessContentHeartbeatFrame, HarnessContentMarkerView, HarnessContentPosition,
            HarnessContentRecordView, HarnessContentRecordsFrame, HarnessContentResetReason,
            HarnessContentResetRequiredFrame, HarnessContentStreamFrame,
            HarnessLifecycleContentView, HarnessUsageContentView, ProjectionHealth,
            harness_artifact_relation_view, harness_content_record_view,
            harness_content_stream_frame,
        },
    },
};
use prost::Message;
use prost_types::Timestamp;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{LocalReadModel, ProjectionFailure, sha256};

const CONTENT_EVENT_KIND_RECORD: i32 = 1;
const MAX_SAFE_TEXT_BYTES: usize = 65_536;
const MAX_ATTEMPT_SAFE_TEXT_BYTES: u64 = 16_777_216;
const MAX_ATTEMPT_SAFE_RECORDS: u64 = 16_384;
const MAX_TASK_SAFE_TEXT_BYTES: u64 = 67_108_864;
const MAX_TASK_SAFE_RECORDS: u64 = 65_536;
const MAX_PAGE_RECORDS: usize = 256;
const MAX_PAGE_TEXT_BYTES: usize = 1_048_576;
const MAX_SERIALIZED_FRAME_BYTES: usize = 81_920;
const MAX_WATCH_FRAMES: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HarnessContentReadAccess {
    /// Set only after Local API has verified `local.harness.content.read`.
    pub can_read_content: bool,
    /// Set only after Local API has separately verified `local.evidence.read`.
    pub can_read_artifact_identity: bool,
}

#[derive(Clone, Debug)]
pub struct HarnessContentProjectionInput {
    /// Stable Adapter acknowledged-outbox identity.
    pub delivery_id: String,
    /// SHA-256 of the exact encoded `event` bytes stored in the outbox.
    pub payload_digest_sha256: String,
    pub event: SafeHarnessContentProjectionEvent,
    pub projected_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessContentApply {
    Committed {
        position: HarnessContentPosition,
        record_id: String,
    },
    Replay {
        original_position: HarnessContentPosition,
    },
}

/// In-process cursor material. R9C.3 places this inside the Local API's opaque,
/// integrity-protected token envelope; callers cannot substitute filters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessContentPageCursor {
    epoch: String,
    snapshot_sequence: u64,
    task_id: String,
    attempt_ids: Vec<String>,
    last_sequence: u64,
}

impl HarnessContentPageCursor {
    #[must_use]
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

#[derive(Clone, Debug)]
pub struct HarnessContentBaselineQuery {
    pub task_id: String,
    pub attempt_ids: Vec<String>,
    pub page_size: u32,
    /// Omitted on the first page and required with `cursor` thereafter.
    pub snapshot_position: Option<HarnessContentPosition>,
    pub cursor: Option<HarnessContentPageCursor>,
}

#[derive(Clone, Debug)]
pub struct HarnessContentBaselineResult {
    pub records: Vec<HarnessContentRecordView>,
    pub next_cursor: Option<HarnessContentPageCursor>,
    pub has_more: bool,
    pub snapshot_position: HarnessContentPosition,
    pub retained_from_sequence: u64,
    pub disclosure_profile_ref: ContractReference,
}

#[derive(Clone, Debug)]
pub struct HarnessContentWatchQuery {
    pub task_id: String,
    pub attempt_ids: Vec<String>,
    pub resume_after: HarnessContentPosition,
    pub max_frames: u32,
}

#[derive(Clone, Debug)]
pub struct HarnessContentWatchResult {
    /// Last position represented by the returned batch. A heartbeat/reset uses
    /// the current content-domain position.
    pub observed_position: HarnessContentPosition,
    pub frames: Vec<HarnessContentStreamFrame>,
}

pub(crate) fn initialize_content_domain(
    connection: &Connection,
    initial_epoch: &str,
) -> Result<(), ProjectionFailure> {
    if initial_epoch.trim().is_empty() {
        return Err(ProjectionFailure::StoreGenerationMismatch);
    }
    let embedded_profile_is_valid = ContractProfiles::embedded().is_ok();
    connection.execute(
        "INSERT OR IGNORE INTO harness_content_metadata(
           singleton,epoch,current_sequence,retention_floor_sequence,health,
           current_projected_at_seconds,current_projected_at_nanos,
           disclosure_contract_id,disclosure_contract_version,
           disclosure_profile_id,disclosure_profile_sha256
         ) VALUES(1,?1,0,0,?2,0,0,?3,?4,?5,?6)",
        params![
            initial_epoch,
            ProjectionHealth::Ready as i32,
            HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID,
            HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
            HARNESS_CONTENT_DISCLOSURE_PROFILE_ID,
            HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
        ],
    )?;
    let actual: (String, String, String, String, String, i32) = connection.query_row(
        "SELECT epoch,disclosure_contract_id,disclosure_contract_version,
                disclosure_profile_id,disclosure_profile_sha256,health
         FROM harness_content_metadata WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    let profile_matches = actual.1 == HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
        && actual.2 == HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION
        && actual.3 == HARNESS_CONTENT_DISCLOSURE_PROFILE_ID
        && actual.4 == HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256;
    if !embedded_profile_is_valid || !profile_matches {
        connection.execute(
            "UPDATE harness_content_metadata SET health=?1,reset_reason=?2 WHERE singleton=1",
            params![
                ProjectionHealth::Held as i32,
                HarnessContentResetReason::ProfileChanged as i32
            ],
        )?;
    } else if actual.0.trim().is_empty() || ProjectionHealth::try_from(actual.5).is_err() {
        connection.execute(
            "UPDATE harness_content_metadata SET health=?1,reset_reason=?2 WHERE singleton=1",
            params![
                ProjectionHealth::IntegrityFailed as i32,
                HarnessContentResetReason::IntegrityRecovery as i32
            ],
        )?;
    }
    Ok(())
}

impl LocalReadModel {
    pub fn apply_harness_content(
        &mut self,
        input: &HarnessContentProjectionInput,
    ) -> Result<HarnessContentApply, ProjectionFailure> {
        validate_projection_input(input)?;
        let event_bytes = input.event.encode_to_vec();
        let record = match input.event.payload.as_ref() {
            Some(safe_harness_content_projection_event::Payload::ContentRecord(record)) => record,
            Some(
                safe_harness_content_projection_event::Payload::HistoryCompaction(_)
                | safe_harness_content_projection_event::Payload::RetentionTombstone(_),
            ) => return Err(ProjectionFailure::ContentOwnerSnapshotRequired),
            None => return Err(ProjectionFailure::InvalidMessage),
        };
        let safe_text_bytes = validate_safe_record(record)?;

        let result = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let result = apply_content_record_transaction(
                &transaction,
                input,
                record,
                &event_bytes,
                safe_text_bytes,
            );
            match result {
                Ok(ApplyTransaction::Committed { sequence }) => {
                    transaction.commit()?;
                    Ok(HarnessContentApply::Committed {
                        position: content_position_at_connection(
                            &self.connection,
                            sequence,
                            Some(input.projected_at),
                        )?,
                        record_id: record.record_id.clone(),
                    })
                }
                Ok(ApplyTransaction::Replay {
                    sequence,
                    projected_at,
                }) => {
                    transaction.commit()?;
                    Ok(HarnessContentApply::Replay {
                        original_position: content_position_at_connection(
                            &self.connection,
                            sequence,
                            Some(projected_at),
                        )?,
                    })
                }
                Err(error) => Err(error),
            }
        };
        if matches!(result, Err(ProjectionFailure::IntegrityFailure)) {
            mark_content_integrity_failed(&self.connection)?;
        }
        result
    }

    pub fn harness_content_position(&self) -> Result<HarnessContentPosition, ProjectionFailure> {
        let (epoch, sequence, seconds, nanos): (String, i64, i64, i32) =
            self.connection.query_row(
                "SELECT epoch,current_sequence,current_projected_at_seconds,
                        current_projected_at_nanos
                 FROM harness_content_metadata WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        Ok(HarnessContentPosition {
            epoch,
            sequence: sequence as u64,
            projected_at: (sequence > 0).then_some(Timestamp { seconds, nanos }),
        })
    }

    pub fn harness_content_retention_floor(
        &self,
    ) -> Result<HarnessContentPosition, ProjectionFailure> {
        let (epoch, sequence): (String, i64) = self.connection.query_row(
            "SELECT epoch,retention_floor_sequence
             FROM harness_content_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(HarnessContentPosition {
            epoch,
            sequence: sequence as u64,
            projected_at: None,
        })
    }

    pub fn harness_content_health(&self) -> Result<ProjectionHealth, ProjectionFailure> {
        let value: i32 = self.connection.query_row(
            "SELECT health FROM harness_content_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ProjectionHealth::try_from(value).map_err(|_| ProjectionFailure::IntegrityFailure)
    }

    pub fn list_harness_content(
        &self,
        query: &HarnessContentBaselineQuery,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentBaselineResult, ProjectionFailure> {
        if !access.can_read_content {
            return Err(ProjectionFailure::PermissionDenied);
        }
        // A baseline is defined at one fixed projection position. Keep the
        // metadata, floor and record scan on the same SQLite read snapshot so
        // a concurrent projector commit cannot split those observations.
        let snapshot = self.connection.unchecked_transaction()?;
        let result = self.list_harness_content_inner(query, access);
        match result {
            Ok(value) => {
                snapshot.commit()?;
                Ok(value)
            }
            Err(error) => {
                snapshot.rollback()?;
                if matches!(error, ProjectionFailure::IntegrityFailure) {
                    mark_content_integrity_failed(&self.connection)?;
                }
                Err(error)
            }
        }
    }

    fn list_harness_content_inner(
        &self,
        query: &HarnessContentBaselineQuery,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentBaselineResult, ProjectionFailure> {
        let attempt_ids = validate_query(&query.task_id, &query.attempt_ids)?;
        if query.page_size == 0 {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let current = self.harness_content_position()?;
        let floor = self.harness_content_retention_floor()?;
        if self.harness_content_health()? != ProjectionHealth::Ready {
            return Err(ProjectionFailure::ContentBaselineUnavailable);
        }

        let (snapshot, after_sequence, continuation) =
            match (&query.cursor, &query.snapshot_position) {
                (None, None) => (current.clone(), floor.sequence.saturating_sub(1), false),
                (Some(cursor), Some(snapshot)) => {
                    if cursor.epoch != snapshot.epoch
                        || cursor.snapshot_sequence != snapshot.sequence
                        || cursor.task_id != query.task_id
                        || cursor.attempt_ids != attempt_ids
                    {
                        return Err(ProjectionFailure::ContentCursorMismatch);
                    }
                    (snapshot.clone(), cursor.last_sequence, true)
                }
                _ => return Err(ProjectionFailure::ContentCursorMismatch),
            };
        validate_snapshot(&snapshot, &current, &floor)?;
        if after_sequence > snapshot.sequence || (continuation && after_sequence < floor.sequence) {
            return Err(ProjectionFailure::ContentCursorMismatch);
        }

        let record_limit = usize::try_from(query.page_size)
            .unwrap_or(MAX_PAGE_RECORDS)
            .min(MAX_PAGE_RECORDS);
        let allowed_attempts = attempt_ids.iter().cloned().collect::<BTreeSet<_>>();
        let mut statement = self.connection.prepare(
            "SELECT content_sequence,record_id,content_event_id,record_digest_sha256,
                    task_id,attempt_id,disclosure_contract_id,
                    disclosure_contract_version,disclosure_profile_sha256,
                    safe_text_bytes,projected_at_seconds,projected_at_nanos,safe_record
             FROM harness_content_records
             WHERE task_id=?1 AND content_sequence>?2 AND content_sequence<=?3
             ORDER BY content_sequence",
        )?;
        let mut rows = statement.query(params![
            query.task_id,
            after_sequence as i64,
            snapshot.sequence as i64
        ])?;
        let mut records = Vec::new();
        let mut text_bytes = 0usize;
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            let persisted = PersistedRecord::from_row(row)?;
            if !allowed_attempts.is_empty() && !allowed_attempts.contains(&persisted.attempt_id) {
                continue;
            }
            if records.len() == record_limit
                || text_bytes.saturating_add(persisted.safe_text_bytes) > MAX_PAGE_TEXT_BYTES
            {
                has_more = true;
                break;
            }
            let view = persisted.decode_view(access)?;
            text_bytes = text_bytes.saturating_add(persisted.safe_text_bytes);
            records.push(view);
        }
        let next_cursor = if has_more {
            let last_sequence = records
                .last()
                .map(|record| record.content_sequence)
                .ok_or(ProjectionFailure::IntegrityFailure)?;
            Some(HarnessContentPageCursor {
                epoch: snapshot.epoch.clone(),
                snapshot_sequence: snapshot.sequence,
                task_id: query.task_id.clone(),
                attempt_ids,
                last_sequence,
            })
        } else {
            None
        };
        Ok(HarnessContentBaselineResult {
            records,
            next_cursor,
            has_more,
            snapshot_position: snapshot,
            retained_from_sequence: floor.sequence,
            disclosure_profile_ref: disclosure_profile_ref(),
        })
    }

    pub fn watch_harness_content(
        &self,
        query: &HarnessContentWatchQuery,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentWatchResult, ProjectionFailure> {
        if !access.can_read_content {
            return Err(ProjectionFailure::PermissionDenied);
        }
        // Each bounded watch poll is one coherent read snapshot. Transport
        // streaming happens above this layer and starts strictly after the
        // returned position.
        let snapshot = self.connection.unchecked_transaction()?;
        let result = self.watch_harness_content_inner(query, access);
        match result {
            Ok(value) => {
                snapshot.commit()?;
                Ok(value)
            }
            Err(error) => {
                snapshot.rollback()?;
                if matches!(error, ProjectionFailure::IntegrityFailure) {
                    mark_content_integrity_failed(&self.connection)?;
                }
                Err(error)
            }
        }
    }

    fn watch_harness_content_inner(
        &self,
        query: &HarnessContentWatchQuery,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentWatchResult, ProjectionFailure> {
        let attempt_ids = validate_query(&query.task_id, &query.attempt_ids)?;
        let current = self.harness_content_position()?;
        let floor = self.harness_content_retention_floor()?;
        let health = self.harness_content_health()?;
        if health != ProjectionHealth::Ready
            || query.resume_after.epoch != current.epoch
            || query.resume_after.sequence < floor.sequence
            || query.resume_after.sequence > current.sequence
        {
            let reason = if health != ProjectionHealth::Ready {
                self.harness_content_reset_reason()?
            } else if query.resume_after.epoch != current.epoch {
                HarnessContentResetReason::EpochChanged
            } else if query.resume_after.sequence < floor.sequence {
                HarnessContentResetReason::RetentionCompacted
            } else {
                HarnessContentResetReason::BaselineUnavailable
            };
            let frame = reset_frame(current.clone(), reason);
            return Ok(HarnessContentWatchResult {
                observed_position: current,
                frames: vec![frame],
            });
        }
        let allowed_attempts = attempt_ids.into_iter().collect::<BTreeSet<_>>();
        let max_frames = if query.max_frames == 0 {
            1
        } else {
            usize::try_from(query.max_frames)
                .unwrap_or(MAX_WATCH_FRAMES)
                .min(MAX_WATCH_FRAMES)
        };
        let mut statement = self.connection.prepare(
            "SELECT content_sequence,record_id,content_event_id,record_digest_sha256,
                    task_id,attempt_id,disclosure_contract_id,
                    disclosure_contract_version,disclosure_profile_sha256,
                    safe_text_bytes,projected_at_seconds,projected_at_nanos,safe_record
             FROM harness_content_records
             WHERE task_id=?1 AND content_sequence>?2 AND content_sequence<=?3
             ORDER BY content_sequence",
        )?;
        let mut rows = statement.query(params![
            query.task_id,
            query.resume_after.sequence as i64,
            current.sequence as i64
        ])?;
        let mut frames = Vec::new();
        while frames.len() < max_frames {
            let Some(row) = rows.next()? else { break };
            let persisted = PersistedRecord::from_row(row)?;
            if !allowed_attempts.is_empty() && !allowed_attempts.contains(&persisted.attempt_id) {
                continue;
            }
            let position = HarnessContentPosition {
                epoch: current.epoch.clone(),
                sequence: persisted.sequence,
                projected_at: Some(persisted.projected_at),
            };
            let frame = HarnessContentStreamFrame {
                position: Some(position),
                payload: Some(harness_content_stream_frame::Payload::Records(
                    HarnessContentRecordsFrame {
                        records: vec![persisted.decode_view(access)?],
                    },
                )),
            };
            if frame.encoded_len() > MAX_SERIALIZED_FRAME_BYTES {
                return Err(ProjectionFailure::IntegrityFailure);
            }
            frames.push(frame);
        }
        if frames.is_empty() {
            frames.push(heartbeat_frame(current.clone()));
        }
        let observed_position = frames
            .last()
            .and_then(|frame| frame.position.clone())
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        Ok(HarnessContentWatchResult {
            observed_position,
            frames,
        })
    }

    /// Fail-closed placeholder for the R9C.2A owner-snapshot rebuild seam.
    ///
    /// No content row, epoch or floor may change until the Adapter-owned
    /// snapshot bundle can be verified and installed in the same transaction.
    pub fn reset_harness_content_for_rebuild(
        &mut self,
        new_epoch: &str,
        reason: HarnessContentResetReason,
    ) -> Result<(), ProjectionFailure> {
        if new_epoch.trim().is_empty() || reason == HarnessContentResetReason::Unspecified {
            return Err(ProjectionFailure::InvalidMessage);
        }
        Err(ProjectionFailure::ContentOwnerSnapshotRequired)
    }

    fn harness_content_reset_reason(&self) -> Result<HarnessContentResetReason, ProjectionFailure> {
        let value: i32 = self.connection.query_row(
            "SELECT reset_reason FROM harness_content_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        match HarnessContentResetReason::try_from(value) {
            Ok(HarnessContentResetReason::Unspecified) => {
                Ok(HarnessContentResetReason::IntegrityRecovery)
            }
            Ok(reason) => Ok(reason),
            Err(_) => Err(ProjectionFailure::IntegrityFailure),
        }
    }
}

enum ApplyTransaction {
    Committed {
        sequence: u64,
    },
    Replay {
        sequence: u64,
        projected_at: Timestamp,
    },
}

fn apply_content_record_transaction(
    transaction: &Transaction<'_>,
    input: &HarnessContentProjectionInput,
    record: &SafeHarnessContentRecord,
    event_bytes: &[u8],
    safe_text_bytes: usize,
) -> Result<ApplyTransaction, ProjectionFailure> {
    let health: i32 = transaction.query_row(
        "SELECT health FROM harness_content_metadata WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if ProjectionHealth::try_from(health) != Ok(ProjectionHealth::Ready) {
        return Err(ProjectionFailure::ContentBaselineUnavailable);
    }
    if let Some(existing) = inbox_by_delivery(transaction, &input.delivery_id)? {
        return replay_or_conflict(
            existing,
            CONTENT_EVENT_KIND_RECORD,
            &record.content_event_id,
            &record.record_digest_sha256,
            &input.payload_digest_sha256,
        );
    }
    if let Some(existing) = inbox_by_owner_event(transaction, &record.content_event_id)? {
        return replay_or_conflict(
            existing,
            CONTENT_EVENT_KIND_RECORD,
            &record.content_event_id,
            &record.record_digest_sha256,
            &input.payload_digest_sha256,
        );
    }
    let conflicting_record: Option<String> = transaction
        .query_row(
            "SELECT content_event_id FROM harness_content_records WHERE record_id=?1",
            [&record.record_id],
            |row| row.get(0),
        )
        .optional()?;
    if conflicting_record.is_some() {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    let tombstoned: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM harness_content_tombstones WHERE task_id=?1 AND attempt_id=?2
         )",
        params![record.task_id, record.attempt_id],
        |row| row.get(0),
    )?;
    if tombstoned {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    enforce_content_budget(transaction, record, safe_text_bytes)?;
    let sequence = next_content_sequence(transaction, &input.projected_at)?;
    let profile = record
        .disclosure_profile_ref
        .as_ref()
        .ok_or(ProjectionFailure::InvalidMessage)?;
    transaction.execute(
        "INSERT INTO harness_content_records(
           content_sequence,record_id,content_event_id,record_digest_sha256,
           delivery_payload_digest_sha256,task_id,attempt_id,
           disclosure_contract_id,disclosure_contract_version,
           disclosure_profile_sha256,safe_text_bytes,projected_at_seconds,
           projected_at_nanos,safe_record
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            sequence as i64,
            record.record_id,
            record.content_event_id,
            record.record_digest_sha256,
            input.payload_digest_sha256,
            record.task_id,
            record.attempt_id,
            profile.contract_id,
            profile.version,
            profile.sha256,
            safe_text_bytes as i64,
            input.projected_at.seconds,
            input.projected_at.nanos,
            record.encode_to_vec(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO harness_content_inbox(
           delivery_id,event_kind,owner_event_id,owner_event_digest_sha256,
           payload_digest_sha256,committed_sequence,projected_at_seconds,
           projected_at_nanos
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            input.delivery_id,
            CONTENT_EVENT_KIND_RECORD,
            record.content_event_id,
            record.record_digest_sha256,
            input.payload_digest_sha256,
            sequence as i64,
            input.projected_at.seconds,
            input.projected_at.nanos,
        ],
    )?;
    // Keep the exact outbox payload verification adjacent to the durable write.
    if sha256(event_bytes) != input.payload_digest_sha256 {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    Ok(ApplyTransaction::Committed { sequence })
}

#[derive(Clone)]
struct InboxRecord {
    event_kind: i32,
    owner_event_id: String,
    owner_event_digest_sha256: String,
    payload_digest_sha256: String,
    sequence: u64,
    projected_at: Timestamp,
}

fn inbox_by_delivery(
    transaction: &Transaction<'_>,
    delivery_id: &str,
) -> Result<Option<InboxRecord>, ProjectionFailure> {
    transaction
        .query_row(
            "SELECT event_kind,owner_event_id,owner_event_digest_sha256,
                    payload_digest_sha256,committed_sequence,
                    projected_at_seconds,projected_at_nanos
             FROM harness_content_inbox WHERE delivery_id=?1",
            [delivery_id],
            inbox_record,
        )
        .optional()
        .map_err(Into::into)
}

fn inbox_by_owner_event(
    transaction: &Transaction<'_>,
    owner_event_id: &str,
) -> Result<Option<InboxRecord>, ProjectionFailure> {
    transaction
        .query_row(
            "SELECT event_kind,owner_event_id,owner_event_digest_sha256,
                    payload_digest_sha256,committed_sequence,
                    projected_at_seconds,projected_at_nanos
             FROM harness_content_inbox WHERE owner_event_id=?1",
            [owner_event_id],
            inbox_record,
        )
        .optional()
        .map_err(Into::into)
}

fn inbox_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<InboxRecord> {
    Ok(InboxRecord {
        event_kind: row.get(0)?,
        owner_event_id: row.get(1)?,
        owner_event_digest_sha256: row.get(2)?,
        payload_digest_sha256: row.get(3)?,
        sequence: row.get::<_, i64>(4)? as u64,
        projected_at: Timestamp {
            seconds: row.get(5)?,
            nanos: row.get(6)?,
        },
    })
}

fn replay_or_conflict(
    existing: InboxRecord,
    event_kind: i32,
    owner_event_id: &str,
    owner_event_digest_sha256: &str,
    payload_digest_sha256: &str,
) -> Result<ApplyTransaction, ProjectionFailure> {
    if existing.event_kind == event_kind
        && existing.owner_event_id == owner_event_id
        && existing.owner_event_digest_sha256 == owner_event_digest_sha256
        && existing.payload_digest_sha256 == payload_digest_sha256
    {
        return Ok(ApplyTransaction::Replay {
            sequence: existing.sequence,
            projected_at: existing.projected_at,
        });
    }
    Err(ProjectionFailure::IntegrityFailure)
}

fn next_content_sequence(
    transaction: &Transaction<'_>,
    projected_at: &Timestamp,
) -> Result<u64, ProjectionFailure> {
    transaction.execute(
        "UPDATE harness_content_metadata
         SET current_sequence=current_sequence+1,
             current_projected_at_seconds=?1,current_projected_at_nanos=?2
         WHERE singleton=1",
        params![projected_at.seconds, projected_at.nanos],
    )?;
    let sequence: i64 = transaction.query_row(
        "SELECT current_sequence FROM harness_content_metadata WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    Ok(sequence as u64)
}

fn enforce_content_budget(
    transaction: &Transaction<'_>,
    record: &SafeHarnessContentRecord,
    safe_text_bytes: usize,
) -> Result<(), ProjectionFailure> {
    let (attempt_records, attempt_bytes): (i64, i64) = transaction.query_row(
        "SELECT count(*),COALESCE(sum(safe_text_bytes),0)
         FROM harness_content_records WHERE task_id=?1 AND attempt_id=?2",
        params![record.task_id, record.attempt_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (task_records, task_bytes): (i64, i64) = transaction.query_row(
        "SELECT count(*),COALESCE(sum(safe_text_bytes),0)
         FROM harness_content_records WHERE task_id=?1",
        [&record.task_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let safe_text_bytes = safe_text_bytes as u64;
    if attempt_records < 0
        || attempt_bytes < 0
        || task_records < 0
        || task_bytes < 0
        || attempt_records as u64 + 1 > MAX_ATTEMPT_SAFE_RECORDS
        || task_records as u64 + 1 > MAX_TASK_SAFE_RECORDS
        || (attempt_bytes as u64).saturating_add(safe_text_bytes) > MAX_ATTEMPT_SAFE_TEXT_BYTES
        || (task_bytes as u64).saturating_add(safe_text_bytes) > MAX_TASK_SAFE_TEXT_BYTES
    {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    Ok(())
}

fn content_position_at_connection(
    connection: &Connection,
    sequence: u64,
    projected_at: Option<Timestamp>,
) -> Result<HarnessContentPosition, ProjectionFailure> {
    let epoch: String = connection.query_row(
        "SELECT epoch FROM harness_content_metadata WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    Ok(HarnessContentPosition {
        epoch,
        sequence,
        projected_at,
    })
}

fn validate_projection_input(
    input: &HarnessContentProjectionInput,
) -> Result<(), ProjectionFailure> {
    if input.delivery_id.trim().is_empty()
        || !is_sha256(&input.payload_digest_sha256)
        || input.projected_at.seconds < 0
        || !(0..1_000_000_000).contains(&input.projected_at.nanos)
        || input.payload_digest_sha256 != sha256(&input.event.encode_to_vec())
    {
        return Err(ProjectionFailure::InvalidMessage);
    }
    Ok(())
}

fn validate_safe_record(record: &SafeHarnessContentRecord) -> Result<usize, ProjectionFailure> {
    if !is_prefixed_sha256(&record.record_id, "hcr_")
        || !is_sha256(&record.record_digest_sha256)
        || !is_sha256(&record.content_event_id)
        || record.task_id.trim().is_empty()
        || record.run_id.trim().is_empty()
        || record.step_id.trim().is_empty()
        || record.attempt_id.trim().is_empty()
        || record.dispatch_id.trim().is_empty()
        || record.fencing_token == 0
        || !is_sha256(&record.route_binding_sha256)
        || record.provider_family_alias.trim().is_empty()
        || record.model_alias.trim().is_empty()
        || record.collaboration_role.trim().is_empty()
    {
        return Err(ProjectionFailure::InvalidMessage);
    }
    validate_profile_ref(record.disclosure_profile_ref.as_ref())?;
    let mut previous = None;
    for value in &record.safety_flags {
        let flag = HarnessContentSafetyFlag::try_from(*value)
            .map_err(|_| ProjectionFailure::InvalidMessage)?;
        if flag == HarnessContentSafetyFlag::Unspecified
            || previous.is_some_and(|prior| prior >= *value)
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        previous = Some(*value);
    }
    match record.payload.as_ref() {
        Some(safe_harness_content_record::Payload::AssistantText(text)) => {
            let operation = ContentMutationOperation::try_from(text.operation)
                .map_err(|_| ProjectionFailure::InvalidMessage)?;
            if !is_prefixed_sha256(&text.safe_message_id, "hcm_")
                || operation == ContentMutationOperation::Unspecified
                || text.revision == 0
                || text.previous_revision >= text.revision
                || (text.revision == 1 && text.previous_revision != 0)
                || (text.revision > 1 && text.previous_revision + 1 != text.revision)
                || !is_sha256(&text.safe_cumulative_digest_sha256)
                || text.part_count == 0
                || text.part_index >= text.part_count
                || text.safe_text_utf8.len() > MAX_SAFE_TEXT_BYTES
            {
                return Err(ProjectionFailure::InvalidMessage);
            }
            Ok(text.safe_text_utf8.len())
        }
        Some(safe_harness_content_record::Payload::Lifecycle(value)) => {
            let kind = LifecycleKind::try_from(value.kind)
                .map_err(|_| ProjectionFailure::InvalidMessage)?;
            let certainty = SideEffectCertainty::try_from(value.side_effect_certainty)
                .map_err(|_| ProjectionFailure::InvalidMessage)?;
            if kind == LifecycleKind::Unspecified || certainty == SideEffectCertainty::Unspecified {
                return Err(ProjectionFailure::InvalidMessage);
            }
            Ok(0)
        }
        Some(safe_harness_content_record::Payload::Usage(_))
        | Some(safe_harness_content_record::Payload::ApprovalRequired(_)) => Ok(0),
        Some(safe_harness_content_record::Payload::ArtifactRelation(value)) => {
            let artifact = value
                .artifact
                .as_ref()
                .ok_or(ProjectionFailure::InvalidMessage)?;
            if artifact.artifact_id.trim().is_empty()
                || !is_sha256(&artifact.artifact_digest_sha256)
            {
                return Err(ProjectionFailure::InvalidMessage);
            }
            Ok(0)
        }
        Some(safe_harness_content_record::Payload::Marker(value)) => {
            let kind = HarnessContentMarkerKind::try_from(value.kind)
                .map_err(|_| ProjectionFailure::InvalidMessage)?;
            if kind == HarnessContentMarkerKind::Unspecified {
                return Err(ProjectionFailure::InvalidMessage);
            }
            Ok(0)
        }
        None => Err(ProjectionFailure::InvalidMessage),
    }
}

fn validate_profile_ref(profile: Option<&ContractReference>) -> Result<(), ProjectionFailure> {
    let profile = profile.ok_or(ProjectionFailure::InvalidMessage)?;
    if profile.contract_id != HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
        || profile.version != HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION
        || profile.sha256 != HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
    {
        return Err(ProjectionFailure::InvalidMessage);
    }
    Ok(())
}

fn validate_query(task_id: &str, attempt_ids: &[String]) -> Result<Vec<String>, ProjectionFailure> {
    if task_id.trim().is_empty() || attempt_ids.iter().any(|value| value.trim().is_empty()) {
        return Err(ProjectionFailure::InvalidMessage);
    }
    let mut canonical = attempt_ids.to_vec();
    canonical.sort();
    if canonical.windows(2).any(|values| values[0] == values[1]) {
        return Err(ProjectionFailure::InvalidMessage);
    }
    Ok(canonical)
}

fn validate_snapshot(
    snapshot: &HarnessContentPosition,
    current: &HarnessContentPosition,
    floor: &HarnessContentPosition,
) -> Result<(), ProjectionFailure> {
    if snapshot.epoch != current.epoch {
        return Err(ProjectionFailure::SnapshotEpochMismatch);
    }
    if snapshot.sequence > current.sequence {
        return Err(ProjectionFailure::SnapshotAhead);
    }
    if snapshot.sequence < floor.sequence {
        return Err(ProjectionFailure::SnapshotBeforeRetention {
            requested: snapshot.sequence,
            floor: floor.sequence,
        });
    }
    Ok(())
}

struct PersistedRecord {
    sequence: u64,
    record_id: String,
    content_event_id: String,
    record_digest_sha256: String,
    task_id: String,
    attempt_id: String,
    contract_id: String,
    contract_version: String,
    profile_sha256: String,
    safe_text_bytes: usize,
    projected_at: Timestamp,
    bytes: Vec<u8>,
}

impl PersistedRecord {
    fn from_row(row: &rusqlite::Row<'_>) -> Result<Self, ProjectionFailure> {
        let sequence = row.get::<_, i64>(0)?;
        let safe_text_bytes = row.get::<_, i64>(9)?;
        if sequence < 1 || safe_text_bytes < 0 {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        if safe_text_bytes as usize > MAX_SAFE_TEXT_BYTES {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        Ok(Self {
            sequence: sequence as u64,
            record_id: row.get(1)?,
            content_event_id: row.get(2)?,
            record_digest_sha256: row.get(3)?,
            task_id: row.get(4)?,
            attempt_id: row.get(5)?,
            contract_id: row.get(6)?,
            contract_version: row.get(7)?,
            profile_sha256: row.get(8)?,
            safe_text_bytes: safe_text_bytes as usize,
            projected_at: Timestamp {
                seconds: row.get(10)?,
                nanos: row.get(11)?,
            },
            bytes: row.get(12)?,
        })
    }

    fn decode_view(
        &self,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentRecordView, ProjectionFailure> {
        let record = SafeHarnessContentRecord::decode(self.bytes.as_slice())
            .map_err(|_| ProjectionFailure::IntegrityFailure)?;
        let text_bytes =
            validate_safe_record(&record).map_err(|_| ProjectionFailure::IntegrityFailure)?;
        let profile = record
            .disclosure_profile_ref
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        if record.record_id != self.record_id
            || record.content_event_id != self.content_event_id
            || record.record_digest_sha256 != self.record_digest_sha256
            || record.task_id != self.task_id
            || record.attempt_id != self.attempt_id
            || profile.contract_id != self.contract_id
            || profile.version != self.contract_version
            || profile.sha256 != self.profile_sha256
            || text_bytes != self.safe_text_bytes
        {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        safe_record_to_view(record, self.sequence, self.projected_at, access)
    }
}

fn safe_record_to_view(
    record: SafeHarnessContentRecord,
    sequence: u64,
    projected_at: Timestamp,
    access: HarnessContentReadAccess,
) -> Result<HarnessContentRecordView, ProjectionFailure> {
    let provisional = record
        .safety_flags
        .contains(&(HarnessContentSafetyFlag::Provisional as i32));
    let payload = match record.payload {
        Some(safe_harness_content_record::Payload::AssistantText(value)) => {
            harness_content_record_view::Payload::AssistantText(HarnessAssistantTextView {
                safe_message_id: value.safe_message_id,
                revision: value.revision,
                previous_revision: value.previous_revision,
                operation: value.operation,
                safe_text_utf8: value.safe_text_utf8,
                safe_cumulative_digest_sha256: value.safe_cumulative_digest_sha256,
                part_index: value.part_index,
                part_count: value.part_count,
                provisional,
            })
        }
        Some(safe_harness_content_record::Payload::Lifecycle(value)) => {
            harness_content_record_view::Payload::Lifecycle(HarnessLifecycleContentView {
                kind: value.kind,
                side_effect_certainty: value.side_effect_certainty,
                native_will_retry: value.native_will_retry,
            })
        }
        Some(safe_harness_content_record::Payload::Usage(value)) => {
            harness_content_record_view::Payload::Usage(HarnessUsageContentView {
                input_tokens: value.input_tokens,
                output_tokens: value.output_tokens,
                cached_input_tokens: value.cached_input_tokens,
            })
        }
        Some(safe_harness_content_record::Payload::ApprovalRequired(_)) => {
            harness_content_record_view::Payload::ApprovalRequired(
                HarnessApprovalRequiredContentView {},
            )
        }
        Some(safe_harness_content_record::Payload::ArtifactRelation(value)) => {
            let artifact = value.artifact.ok_or(ProjectionFailure::IntegrityFailure)?;
            let visibility = if access.can_read_artifact_identity {
                harness_artifact_relation_view::Visibility::Available(HarnessArtifactIdentityView {
                    artifact_id: artifact.artifact_id,
                    artifact_digest_sha256: artifact.artifact_digest_sha256,
                })
            } else {
                harness_artifact_relation_view::Visibility::AvailableRedacted(
                    HarnessArtifactAvailableRedactedView {},
                )
            };
            harness_content_record_view::Payload::ArtifactRelation(HarnessArtifactRelationView {
                safe_content_differs_from_artifact: value.safe_content_differs_from_artifact,
                visibility: Some(visibility),
            })
        }
        Some(safe_harness_content_record::Payload::Marker(value)) => {
            harness_content_record_view::Payload::Marker(HarnessContentMarkerView {
                kind: value.kind,
            })
        }
        None => return Err(ProjectionFailure::IntegrityFailure),
    };
    Ok(HarnessContentRecordView {
        record_id: record.record_id,
        record_digest_sha256: record.record_digest_sha256,
        content_sequence: sequence,
        task_id: record.task_id,
        attempt_id: record.attempt_id,
        provider_family_alias: record.provider_family_alias,
        model_alias: record.model_alias,
        collaboration_role: record.collaboration_role,
        disclosure_profile_ref: record.disclosure_profile_ref,
        projected_at: Some(projected_at),
        safety_flags: record.safety_flags,
        payload: Some(payload),
    })
}

fn disclosure_profile_ref() -> ContractReference {
    ContractReference {
        contract_id: HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID.to_owned(),
        version: HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION.to_owned(),
        sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.to_owned(),
    }
}

fn heartbeat_frame(position: HarnessContentPosition) -> HarnessContentStreamFrame {
    HarnessContentStreamFrame {
        position: Some(position),
        payload: Some(harness_content_stream_frame::Payload::Heartbeat(
            HarnessContentHeartbeatFrame {},
        )),
    }
}

fn reset_frame(
    position: HarnessContentPosition,
    reason: HarnessContentResetReason,
) -> HarnessContentStreamFrame {
    HarnessContentStreamFrame {
        position: Some(position),
        payload: Some(harness_content_stream_frame::Payload::ResetRequired(
            HarnessContentResetRequiredFrame {
                reason: reason as i32,
            },
        )),
    }
}

fn mark_content_integrity_failed(connection: &Connection) -> Result<(), ProjectionFailure> {
    connection.execute(
        "UPDATE harness_content_metadata SET health=?1,reset_reason=?2 WHERE singleton=1",
        params![
            ProjectionHealth::IntegrityFailed as i32,
            HarnessContentResetReason::IntegrityRecovery as i32
        ],
    )?;
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_sha256)
}
