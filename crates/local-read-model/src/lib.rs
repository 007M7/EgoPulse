#![forbid(unsafe_code)]
//! Rebuildable local projection boundary for C-07/G4-08.
//!
//! This crate owns derived state only. It accepts typed, owner-produced
//! projection messages and never receives an Authority database handle.

use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    CollaborationCommandResult, CollaborationSnapshot, collaboration_command_result,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalRequestLifecycleKind, HarnessObservation, harness_observation,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    AvailableAction, AvailableActionKind, HarnessApprovalDecisionView, HarnessApprovalView,
    HarnessApprovalViewStreamFrame, ProjectionHealth, ProjectionMetadata, ProjectionPosition,
    RedactedField, SourceDomain, SourceRevision, StreamFrameKind,
};
use egopulse_domain_contracts::v01::egopulse::policy::v1::PolicyDecisionCommandResult;
use prost::Message;
use prost_types::Timestamp;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

const SCHEMA_PROFILE_ID: &str = "egopulse/local-read-model-store/v1";
const VIEW_CONTRACT_ID: &str = "egopulse.localapi.v1/HarnessApprovalView";
const VIEW_CONTRACT_VERSION: &str = "0.1.0-draft.14";
const VIEW_CONTRACT_SHA256: &str =
    "8eadb3686c8dfe76bf8b56fa48d8a76bd7fa57c177804b132eac793d33b7379e";
const DECIDE_RULE_REF: &str = "egopulse/local-read-model/approval-actionable/v1";

const SCHEMA_V1: &str = r#"
CREATE TABLE projection_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  current_sequence INTEGER NOT NULL DEFAULT 0 CHECK (current_sequence >= 0),
  health INTEGER NOT NULL
) STRICT;
CREATE TABLE projection_inbox (
  source_domain INTEGER NOT NULL,
  message_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  message_mode INTEGER NOT NULL,
  payload_digest_sha256 TEXT NOT NULL,
  committed_sequence INTEGER,
  PRIMARY KEY (source_domain, message_id)
) STRICT;
CREATE TABLE collaboration_projections (
  run_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;
CREATE TABLE approval_request_projections (
  approval_request_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  request_revision INTEGER NOT NULL CHECK (request_revision >= 1),
  request_lifecycle INTEGER NOT NULL,
  run_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  dispatch_id TEXT NOT NULL,
  fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
  observation BLOB NOT NULL
) STRICT;
CREATE TABLE policy_decision_projections (
  approval_request_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  result BLOB NOT NULL
) STRICT;
CREATE TABLE harness_approval_views (
  approval_request_id TEXT PRIMARY KEY,
  updated_sequence INTEGER NOT NULL CHECK (updated_sequence >= 1),
  view BLOB NOT NULL
) STRICT;
CREATE TABLE harness_approval_frames (
  sequence INTEGER NOT NULL,
  approval_request_id TEXT NOT NULL,
  frame BLOB NOT NULL,
  PRIMARY KEY (sequence, approval_request_id)
) STRICT;
"#;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProjectionMessageMode {
    #[default]
    Incremental = 1,
    RebuildBaseline = 2,
}

#[derive(Clone, Debug)]
pub struct ProjectionMessageMetadata {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub mode: ProjectionMessageMode,
    pub payload_digest_sha256: String,
    pub projected_at: Timestamp,
}

#[derive(Clone, Debug)]
pub struct CollaborationProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub result: CollaborationCommandResult,
}

#[derive(Clone, Debug)]
pub struct AdapterApprovalProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub run_id: String,
    pub step_id: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub fencing_token: u64,
    pub observation: HarnessObservation,
}

#[derive(Clone, Debug)]
pub struct PolicyApprovalProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub result: PolicyDecisionCommandResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalViewAccess {
    pub can_read: bool,
    pub can_decide: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApprovalListFilter {
    pub request_lifecycles: Vec<i32>,
    pub decision_states: Vec<i32>,
    pub task_ids: Vec<String>,
    pub actionable_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionApply {
    Committed {
        position: ProjectionPosition,
        changed_approval_ids: Vec<String>,
    },
    Replay {
        position: ProjectionPosition,
    },
}

pub struct LocalReadModelKey(Zeroizing<[u8; 32]>);

impl LocalReadModelKey {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct LocalReadModelConfig {
    pub database_path: PathBuf,
    pub epoch: String,
    pub key: LocalReadModelKey,
}

#[derive(Debug, Error)]
pub enum ProjectionFailure {
    #[error("local read model storage operation failed")]
    Storage(#[from] rusqlite::Error),
    #[error("local read model migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("local read model directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("local read model SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("local read model generation does not match configuration")]
    StoreGenerationMismatch,
    #[error("projection payload could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("projection message is incomplete or has an invalid digest")]
    InvalidMessage,
    #[error("projection source revision is stale or out of order")]
    StaleSourceRevision,
    #[error("projection rebuild baseline is not allowed in the current state")]
    RebuildBaselineNotAllowed,
    #[error("projection cross-source integrity check failed")]
    IntegrityFailure,
    #[error("projection read is not authorized")]
    PermissionDenied,
}

pub struct LocalReadModel {
    connection: Connection,
}

impl LocalReadModel {
    pub fn open(config: LocalReadModelConfig) -> Result<Self, ProjectionFailure> {
        if config.epoch.trim().is_empty() {
            return Err(ProjectionFailure::StoreGenerationMismatch);
        }
        if let Some(parent) = config.database_path.parent() {
            fs::create_dir_all(parent).map_err(ProjectionFailure::Directory)?;
        }
        let mut connection = Connection::open(&config.database_path)?;
        connection.pragma_update(
            None,
            "key",
            format!("x'{}'", hex::encode(config.key.expose())),
        )?;
        let cipher: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|_| ProjectionFailure::CipherUnavailable)?;
        if cipher.trim().is_empty() {
            return Err(ProjectionFailure::CipherUnavailable);
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        Migrations::new(vec![M::up(SCHEMA_V1)]).to_latest(&mut connection)?;
        let digest = sha256(SCHEMA_V1.as_bytes());
        connection.execute(
            "INSERT OR IGNORE INTO projection_metadata(
               singleton,epoch,schema_profile_id,schema_profile_sha256,current_sequence,health
             ) VALUES(1,?1,?2,?3,0,?4)",
            params![
                config.epoch,
                SCHEMA_PROFILE_ID,
                digest,
                ProjectionHealth::Ready as i32
            ],
        )?;
        let actual: (String, String, String) = connection.query_row(
            "SELECT epoch,schema_profile_id,schema_profile_sha256
             FROM projection_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if actual != (config.epoch, SCHEMA_PROFILE_ID.to_owned(), digest) {
            return Err(ProjectionFailure::StoreGenerationMismatch);
        }
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        Ok(Self { connection })
    }

    pub fn apply_collaboration(
        &mut self,
        input: &CollaborationProjectionInput,
    ) -> Result<ProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.result.encode_to_vec())?;
        let snapshot = match input.result.outcome.as_ref() {
            Some(collaboration_command_result::Outcome::Snapshot(value)) => value,
            _ => return Err(ProjectionFailure::InvalidMessage),
        };
        let event = input
            .result
            .committed_event
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let run = snapshot
            .run
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        if event.event_id != input.metadata.source_event_id
            || event.resulting_run_revision != input.metadata.source_revision
            || run.revision != input.metadata.source_revision
            || run.run_id.trim().is_empty()
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::Collaboration, &input.metadata)? {
                return Ok(None);
            }
            let changed = upsert_collaboration(tx, snapshot, &input.metadata)?;
            if !changed {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            let ids = approval_ids_for_run(tx, &run.run_id)?;
            for id in &ids {
                recompute_approval_view(tx, id, sequence, &input.metadata.projected_at)?;
            }
            bind_inbox_sequence(tx, SourceDomain::Collaboration, &input.metadata, sequence)?;
            Ok(Some((sequence, ids)))
        });
        self.finish_apply(result, &input.metadata.projected_at)
    }

    pub fn apply_adapter_approval(
        &mut self,
        input: &AdapterApprovalProjectionInput,
    ) -> Result<ProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.observation.encode_to_vec())?;
        if input.metadata.mode != ProjectionMessageMode::Incremental {
            return Err(ProjectionFailure::RebuildBaselineNotAllowed);
        }
        let request = match input.observation.payload.as_ref() {
            Some(harness_observation::Payload::ApprovalRequest(value)) => value,
            _ => return Err(ProjectionFailure::InvalidMessage),
        };
        if input.observation.observation_id != input.metadata.source_event_id
            || input.observation.observation_sequence != input.metadata.source_revision
            || input.observation.attempt_id != input.attempt_id
            || input.observation.dispatch_id != input.dispatch_id
            || input.observation.fencing_token != input.fencing_token
            || request.approval_request_id.trim().is_empty()
            || request.request_revision == 0
            || !request.native_routing_ref.is_empty()
            || input.run_id.trim().is_empty()
            || input.step_id.trim().is_empty()
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let approval_id = request.approval_request_id.clone();
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::HarnessAdapter, &input.metadata)? {
                return Ok(None);
            }
            let changed = upsert_approval_request(tx, input, request.request_revision)?;
            if !changed {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            recompute_approval_view(tx, &approval_id, sequence, &input.metadata.projected_at)?;
            bind_inbox_sequence(tx, SourceDomain::HarnessAdapter, &input.metadata, sequence)?;
            Ok(Some((sequence, vec![approval_id])))
        });
        self.finish_apply(result, &input.metadata.projected_at)
    }

    pub fn apply_policy_approval(
        &mut self,
        input: &PolicyApprovalProjectionInput,
    ) -> Result<ProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.result.encode_to_vec())?;
        let event = input
            .result
            .event
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let record = input
            .result
            .decision_record
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let state = input
            .result
            .state
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let request = record
            .request
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        if event.event_id != input.metadata.source_event_id
            || event.resulting_state_revision != input.metadata.source_revision
            || state.revision != input.metadata.source_revision
            || state.authority_decision_ref != record.authority_decision_ref
            || request.approval_request_id.trim().is_empty()
            || !request.native_routing_ref.is_empty()
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let approval_id = request.approval_request_id.clone();
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::PolicyDecision, &input.metadata)? {
                return Ok(None);
            }
            let changed = upsert_policy_decision(tx, &approval_id, input)?;
            if !changed {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            recompute_approval_view(tx, &approval_id, sequence, &input.metadata.projected_at)?;
            bind_inbox_sequence(tx, SourceDomain::PolicyDecision, &input.metadata, sequence)?;
            Ok(Some((sequence, vec![approval_id])))
        });
        self.finish_apply(result, &input.metadata.projected_at)
    }

    pub fn get_harness_approval_view(
        &self,
        approval_request_id: &str,
        access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let health = self.health()?;
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT view FROM harness_approval_views WHERE approval_request_id=?1",
                [approval_request_id],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|bytes| {
                let mut view = HarnessApprovalView::decode(bytes.as_slice())?;
                apply_access(&mut view, access, health);
                Ok(view)
            })
            .transpose()
    }

    pub fn list_harness_approval_views(
        &self,
        filter: &ApprovalListFilter,
        access: ApprovalViewAccess,
    ) -> Result<Vec<HarnessApprovalView>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let health = self.health()?;
        let mut statement = self.connection.prepare(
            "SELECT view FROM harness_approval_views
             ORDER BY updated_sequence DESC, approval_request_id ASC",
        )?;
        let payloads = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut views = Vec::new();
        for payload in payloads {
            let mut view = HarnessApprovalView::decode(payload.as_slice())?;
            apply_access(&mut view, access, health);
            let decision_state = view.policy_decision.as_ref().map(|value| value.state);
            if (!filter.request_lifecycles.is_empty()
                && !filter.request_lifecycles.contains(&view.request_lifecycle))
                || (!filter.decision_states.is_empty()
                    && !decision_state.is_some_and(|value| filter.decision_states.contains(&value)))
                || (!filter.task_ids.is_empty() && !filter.task_ids.contains(&view.task_id))
                || (filter.actionable_only && view.available_actions.is_empty())
            {
                continue;
            }
            views.push(view);
        }
        Ok(views)
    }

    pub fn approval_frames_after(
        &self,
        after: &ProjectionPosition,
        access: ApprovalViewAccess,
    ) -> Result<Vec<HarnessApprovalViewStreamFrame>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let current = self.position()?;
        let health = self.health()?;
        if after.epoch != current.epoch
            || after.sequence > current.sequence
            || health != ProjectionHealth::Ready
        {
            return Ok(vec![HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::ResetRequired as i32,
                position: Some(current),
                snapshot: None,
                reset_reason_code: Some(if health == ProjectionHealth::Ready {
                    "PROJECTION_EPOCH_OR_POSITION_INVALID".to_owned()
                } else {
                    "PROJECTION_NOT_READY".to_owned()
                }),
            }]);
        }
        let mut statement = self.connection.prepare(
            "SELECT frame FROM harness_approval_frames
             WHERE sequence>?1 ORDER BY sequence,approval_request_id",
        )?;
        let payloads = statement
            .query_map([after.sequence as i64], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        payloads
            .into_iter()
            .map(|payload| {
                let mut frame = HarnessApprovalViewStreamFrame::decode(payload.as_slice())?;
                if let Some(view) = frame.snapshot.as_mut() {
                    apply_access(view, access, health);
                }
                Ok(frame)
            })
            .collect()
    }

    pub fn position(&self) -> Result<ProjectionPosition, ProjectionFailure> {
        let (epoch, sequence): (String, i64) = self.connection.query_row(
            "SELECT epoch,current_sequence FROM projection_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(ProjectionPosition {
            epoch,
            sequence: sequence as u64,
            projected_at: None,
        })
    }

    pub fn health(&self) -> Result<ProjectionHealth, ProjectionFailure> {
        let value: i32 = self.connection.query_row(
            "SELECT health FROM projection_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ProjectionHealth::try_from(value).map_err(|_| ProjectionFailure::IntegrityFailure)
    }

    pub fn reset_for_rebuild(&mut self, new_epoch: &str) -> Result<(), ProjectionFailure> {
        if new_epoch.trim().is_empty() {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for table in [
            "projection_inbox",
            "collaboration_projections",
            "approval_request_projections",
            "policy_decision_projections",
            "harness_approval_views",
            "harness_approval_frames",
        ] {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        transaction.execute(
            "UPDATE projection_metadata SET epoch=?1,current_sequence=0,health=?2
             WHERE singleton=1",
            params![new_epoch, ProjectionHealth::Rebuilding as i32],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_rebuild_ready(&mut self) -> Result<(), ProjectionFailure> {
        self.connection.execute(
            "UPDATE projection_metadata SET health=?1 WHERE singleton=1",
            [ProjectionHealth::Ready as i32],
        )?;
        Ok(())
    }

    pub fn integrity_is_ok(&self) -> Result<bool, ProjectionFailure> {
        let value: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(value == "ok")
    }

    fn apply_transaction<T>(
        &mut self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ProjectionFailure>,
    ) -> Result<T, ProjectionFailure> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = operation(&transaction);
        match result {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    fn finish_apply(
        &mut self,
        result: Result<Option<(u64, Vec<String>)>, ProjectionFailure>,
        projected_at: &Timestamp,
    ) -> Result<ProjectionApply, ProjectionFailure> {
        match result {
            Ok(Some((sequence, ids))) => Ok(ProjectionApply::Committed {
                position: self.position_at(sequence, projected_at),
                changed_approval_ids: ids,
            }),
            Ok(None) => Ok(ProjectionApply::Replay {
                position: self.position()?,
            }),
            Err(error) => {
                if matches!(
                    error,
                    ProjectionFailure::IntegrityFailure | ProjectionFailure::StaleSourceRevision
                ) {
                    self.connection.execute(
                        "UPDATE projection_metadata SET health=?1 WHERE singleton=1",
                        [ProjectionHealth::IntegrityFailed as i32],
                    )?;
                }
                Err(error)
            }
        }
    }

    fn position_at(&self, sequence: u64, projected_at: &Timestamp) -> ProjectionPosition {
        let epoch = self
            .connection
            .query_row(
                "SELECT epoch FROM projection_metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_default();
        ProjectionPosition {
            epoch,
            sequence,
            projected_at: Some(*projected_at),
        }
    }
}

fn validate_metadata(
    metadata: &ProjectionMessageMetadata,
    payload: &[u8],
) -> Result<(), ProjectionFailure> {
    if metadata.message_id.trim().is_empty()
        || metadata.source_event_id.trim().is_empty()
        || metadata.source_revision == 0
        || metadata.payload_digest_sha256 != sha256(payload)
        || metadata.projected_at.seconds < 0
    {
        return Err(ProjectionFailure::InvalidMessage);
    }
    Ok(())
}

fn register_inbox(
    transaction: &Transaction<'_>,
    domain: SourceDomain,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
    let existing: Option<(String, i64, i32, String)> = transaction
        .query_row(
            "SELECT source_event_id,source_revision,message_mode,payload_digest_sha256
             FROM projection_inbox
             WHERE source_domain=?1 AND message_id=?2",
            params![domain as i32, metadata.message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((event_id, revision, mode, digest)) = existing {
        if event_id == metadata.source_event_id
            && revision == metadata.source_revision as i64
            && mode == metadata.mode as i32
            && digest == metadata.payload_digest_sha256
        {
            return Ok(true);
        }
        return Err(ProjectionFailure::IntegrityFailure);
    }
    transaction.execute(
        "INSERT INTO projection_inbox(
           source_domain,message_id,source_event_id,source_revision,message_mode,
           payload_digest_sha256
         ) VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            domain as i32,
            metadata.message_id,
            metadata.source_event_id,
            metadata.source_revision as i64,
            metadata.mode as i32,
            metadata.payload_digest_sha256
        ],
    )?;
    Ok(false)
}

fn bind_inbox_sequence(
    transaction: &Transaction<'_>,
    domain: SourceDomain,
    metadata: &ProjectionMessageMetadata,
    sequence: u64,
) -> Result<(), ProjectionFailure> {
    transaction.execute(
        "UPDATE projection_inbox SET committed_sequence=?3
         WHERE source_domain=?1 AND message_id=?2",
        params![domain as i32, metadata.message_id, sequence as i64],
    )?;
    Ok(())
}

fn next_sequence(transaction: &Transaction<'_>) -> Result<u64, ProjectionFailure> {
    transaction.execute(
        "UPDATE projection_metadata SET current_sequence=current_sequence+1 WHERE singleton=1",
        [],
    )?;
    let sequence: i64 = transaction.query_row(
        "SELECT current_sequence FROM projection_metadata WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    Ok(sequence as u64)
}

fn upsert_collaboration(
    transaction: &Transaction<'_>,
    snapshot: &CollaborationSnapshot,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(ProjectionFailure::InvalidMessage)?;
    let existing: Option<(i64, String)> = transaction
        .query_row(
            "SELECT source_revision,payload_digest_sha256 FROM collaboration_projections
             WHERE run_id=?1",
            [&run.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((revision, digest)) = existing {
        if metadata.mode == ProjectionMessageMode::RebuildBaseline {
            return Err(ProjectionFailure::RebuildBaselineNotAllowed);
        }
        if metadata.source_revision < revision as u64 {
            return Err(ProjectionFailure::StaleSourceRevision);
        }
        if metadata.source_revision == revision as u64 {
            return if digest == metadata.payload_digest_sha256 {
                Ok(false)
            } else {
                Err(ProjectionFailure::IntegrityFailure)
            };
        }
        if metadata.source_revision != revision as u64 + 1 {
            return Err(ProjectionFailure::StaleSourceRevision);
        }
    } else {
        validate_initial_projection(transaction, metadata)?;
    }
    transaction.execute(
        "INSERT INTO collaboration_projections(
           run_id,source_event_id,source_revision,payload_digest_sha256,snapshot
         ) VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(run_id) DO UPDATE SET
           source_event_id=excluded.source_event_id,
           source_revision=excluded.source_revision,
           payload_digest_sha256=excluded.payload_digest_sha256,
           snapshot=excluded.snapshot",
        params![
            run.run_id,
            metadata.source_event_id,
            metadata.source_revision as i64,
            metadata.payload_digest_sha256,
            snapshot.encode_to_vec()
        ],
    )?;
    Ok(true)
}

fn upsert_approval_request(
    transaction: &Transaction<'_>,
    input: &AdapterApprovalProjectionInput,
    request_revision: u64,
) -> Result<bool, ProjectionFailure> {
    let request = match input.observation.payload.as_ref() {
        Some(harness_observation::Payload::ApprovalRequest(value)) => value,
        _ => return Err(ProjectionFailure::InvalidMessage),
    };
    let lifecycle = ApprovalRequestLifecycleKind::try_from(request.lifecycle)
        .map_err(|_| ProjectionFailure::InvalidMessage)?;
    if lifecycle == ApprovalRequestLifecycleKind::Unspecified {
        return Err(ProjectionFailure::InvalidMessage);
    }
    let existing: Option<(i64, i32, String)> = transaction
        .query_row(
            "SELECT request_revision,request_lifecycle,payload_digest_sha256
             FROM approval_request_projections WHERE approval_request_id=?1",
            [&request.approval_request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((revision, prior_lifecycle, digest)) = existing {
        if request_revision < revision as u64 {
            return Err(ProjectionFailure::StaleSourceRevision);
        }
        if request_revision == revision as u64 {
            return if digest == input.metadata.payload_digest_sha256 {
                Ok(false)
            } else {
                Err(ProjectionFailure::IntegrityFailure)
            };
        }
        if request_revision != revision as u64 + 1
            || prior_lifecycle != ApprovalRequestLifecycleKind::Open as i32
            || lifecycle == ApprovalRequestLifecycleKind::Open
        {
            return Err(ProjectionFailure::StaleSourceRevision);
        }
    } else if request_revision != 1 || lifecycle != ApprovalRequestLifecycleKind::Open {
        return Err(ProjectionFailure::StaleSourceRevision);
    }
    transaction.execute(
        "INSERT INTO approval_request_projections(
           approval_request_id,source_event_id,source_revision,payload_digest_sha256,
           request_revision,request_lifecycle,run_id,step_id,attempt_id,dispatch_id,
           fencing_token,observation
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         ON CONFLICT(approval_request_id) DO UPDATE SET
           source_event_id=excluded.source_event_id,
           source_revision=excluded.source_revision,
           payload_digest_sha256=excluded.payload_digest_sha256,
           request_revision=excluded.request_revision,
           request_lifecycle=excluded.request_lifecycle,
           run_id=excluded.run_id,step_id=excluded.step_id,attempt_id=excluded.attempt_id,
           dispatch_id=excluded.dispatch_id,fencing_token=excluded.fencing_token,
           observation=excluded.observation",
        params![
            request.approval_request_id,
            input.metadata.source_event_id,
            input.metadata.source_revision as i64,
            input.metadata.payload_digest_sha256,
            request_revision as i64,
            request.lifecycle,
            input.run_id,
            input.step_id,
            input.attempt_id,
            input.dispatch_id,
            input.fencing_token as i64,
            input.observation.encode_to_vec()
        ],
    )?;
    Ok(true)
}

fn upsert_policy_decision(
    transaction: &Transaction<'_>,
    approval_id: &str,
    input: &PolicyApprovalProjectionInput,
) -> Result<bool, ProjectionFailure> {
    let existing: Option<(i64, String)> = transaction
        .query_row(
            "SELECT source_revision,payload_digest_sha256 FROM policy_decision_projections
             WHERE approval_request_id=?1",
            [approval_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((revision, digest)) = existing {
        if input.metadata.mode == ProjectionMessageMode::RebuildBaseline {
            return Err(ProjectionFailure::RebuildBaselineNotAllowed);
        }
        if input.metadata.source_revision < revision as u64 {
            return Err(ProjectionFailure::StaleSourceRevision);
        }
        if input.metadata.source_revision == revision as u64 {
            return if digest == input.metadata.payload_digest_sha256 {
                Ok(false)
            } else {
                Err(ProjectionFailure::IntegrityFailure)
            };
        }
        if input.metadata.source_revision != revision as u64 + 1 {
            return Err(ProjectionFailure::StaleSourceRevision);
        }
    } else {
        validate_initial_projection(transaction, &input.metadata)?;
    }
    transaction.execute(
        "INSERT INTO policy_decision_projections(
           approval_request_id,source_event_id,source_revision,payload_digest_sha256,result
         ) VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(approval_request_id) DO UPDATE SET
           source_event_id=excluded.source_event_id,
           source_revision=excluded.source_revision,
           payload_digest_sha256=excluded.payload_digest_sha256,
           result=excluded.result",
        params![
            approval_id,
            input.metadata.source_event_id,
            input.metadata.source_revision as i64,
            input.metadata.payload_digest_sha256,
            input.result.encode_to_vec()
        ],
    )?;
    Ok(true)
}

fn validate_initial_projection(
    transaction: &Transaction<'_>,
    metadata: &ProjectionMessageMetadata,
) -> Result<(), ProjectionFailure> {
    match metadata.mode {
        ProjectionMessageMode::Incremental if metadata.source_revision == 1 => Ok(()),
        ProjectionMessageMode::Incremental => Err(ProjectionFailure::StaleSourceRevision),
        ProjectionMessageMode::RebuildBaseline => {
            let health: i32 = transaction.query_row(
                "SELECT health FROM projection_metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if health == ProjectionHealth::Rebuilding as i32 {
                Ok(())
            } else {
                Err(ProjectionFailure::RebuildBaselineNotAllowed)
            }
        }
    }
}

fn approval_ids_for_run(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<Vec<String>, ProjectionFailure> {
    let mut statement = transaction.prepare(
        "SELECT approval_request_id FROM approval_request_projections
         WHERE run_id=?1 ORDER BY approval_request_id",
    )?;
    let rows = statement.query_map([run_id], |row| row.get(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
fn recompute_approval_view(
    transaction: &Transaction<'_>,
    approval_id: &str,
    sequence: u64,
    projected_at: &Timestamp,
) -> Result<(), ProjectionFailure> {
    type RequestRow = (String, String, u64, String, String, String, u64, Vec<u8>);
    let request_row: Option<RequestRow> = transaction
        .query_row(
            "SELECT source_event_id,run_id,source_revision,step_id,attempt_id,dispatch_id,
                    fencing_token,observation
             FROM approval_request_projections WHERE approval_request_id=?1",
            [approval_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get::<_, i64>(6)? as u64,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        adapter_event,
        run_id,
        adapter_revision,
        step_id,
        attempt_id,
        dispatch_id,
        fence,
        observation_bytes,
    )) = request_row
    else {
        return Ok(());
    };
    let observation = HarnessObservation::decode(observation_bytes.as_slice())?;
    let request = match observation.payload.as_ref() {
        Some(harness_observation::Payload::ApprovalRequest(value)) => value,
        _ => return Err(ProjectionFailure::IntegrityFailure),
    };

    let collaboration: Option<(u64, String, CollaborationSnapshot)> = transaction
        .query_row(
            "SELECT source_revision,source_event_id,snapshot FROM collaboration_projections
             WHERE run_id=?1",
            [&run_id],
            |row| {
                let revision = row.get::<_, i64>(0)? as u64;
                let event_id = row.get(1)?;
                let payload: Vec<u8> = row.get(2)?;
                Ok((revision, event_id, payload))
            },
        )
        .optional()?
        .map(
            |(revision, event_id, payload)| -> Result<_, ProjectionFailure> {
                Ok((
                    revision,
                    event_id,
                    CollaborationSnapshot::decode(payload.as_slice())?,
                ))
            },
        )
        .transpose()?;

    let mut task_id = String::new();
    let mut binding_complete = false;
    let mut source_revisions = vec![SourceRevision {
        domain: SourceDomain::HarnessAdapter as i32,
        aggregate_id: approval_id.to_owned(),
        revision: adapter_revision,
        last_event_id: adapter_event,
    }];
    if let Some((revision, event_id, snapshot)) = collaboration {
        let run = snapshot
            .run
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|value| value.attempt_id == attempt_id)
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        let lease_fence = attempt.lease.as_ref().map(|lease| lease.fencing_token);
        if run.run_id != run_id
            || attempt.run_id != run_id
            || attempt.step_id != step_id
            || attempt.dispatch_id.as_deref() != Some(dispatch_id.as_str())
            || lease_fence != Some(fence)
        {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        task_id = run.task_id.clone();
        binding_complete = !task_id.is_empty();
        source_revisions.push(SourceRevision {
            domain: SourceDomain::Collaboration as i32,
            aggregate_id: run_id.clone(),
            revision,
            last_event_id: event_id,
        });
    }

    let policy: Option<(u64, String, PolicyDecisionCommandResult)> = transaction
        .query_row(
            "SELECT source_revision,source_event_id,result FROM policy_decision_projections
             WHERE approval_request_id=?1",
            [approval_id],
            |row| {
                let revision = row.get::<_, i64>(0)? as u64;
                let event_id = row.get(1)?;
                let payload: Vec<u8> = row.get(2)?;
                Ok((revision, event_id, payload))
            },
        )
        .optional()?
        .map(
            |(revision, event_id, payload)| -> Result<_, ProjectionFailure> {
                Ok((
                    revision,
                    event_id,
                    PolicyDecisionCommandResult::decode(payload.as_slice())?,
                ))
            },
        )
        .transpose()?;

    let policy_decision = if let Some((revision, event_id, result)) = policy {
        let record = result
            .decision_record
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        let state = result
            .state
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        let binding = record
            .request
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        if binding.approval_request_id != approval_id
            || binding.attempt_id != attempt_id
            || binding.dispatch_id != dispatch_id
            || binding.fencing_token != fence
            || binding.action_digest_sha256 != request.action_digest_sha256
            || binding.request_observation_id != observation.observation_id
            || binding.request_observation_sequence != observation.observation_sequence
            || binding.request_revision != request.request_revision
            || binding.request_lifecycle != request.lifecycle
            || state.revision != revision
        {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        source_revisions.push(SourceRevision {
            domain: SourceDomain::PolicyDecision as i32,
            aggregate_id: record.authority_decision_ref.clone(),
            revision,
            last_event_id: event_id,
        });
        Some(HarnessApprovalDecisionView {
            authority_decision_ref: record.authority_decision_ref.clone(),
            decision: record.decision,
            reason_code: record.reason_code.clone(),
            state: state.state,
            state_revision: state.revision,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            updated_at: state.updated_at,
        })
    } else {
        None
    };

    source_revisions.sort_by_key(|value| value.domain);
    let position = ProjectionPosition {
        epoch: projection_epoch(transaction)?,
        sequence,
        projected_at: Some(*projected_at),
    };
    let mut view = HarnessApprovalView {
        metadata: Some(ProjectionMetadata {
            schema_ref: Some(ContractReference {
                contract_id: VIEW_CONTRACT_ID.to_owned(),
                version: VIEW_CONTRACT_VERSION.to_owned(),
                sha256: VIEW_CONTRACT_SHA256.to_owned(),
            }),
            position: Some(position.clone()),
            source_revisions,
            health: ProjectionHealth::Ready as i32,
            stale: false,
            safe_health_reason_code: None,
        }),
        approval_request_id: approval_id.to_owned(),
        task_id,
        run_id,
        step_id,
        attempt_id,
        dispatch_id,
        fencing_token: fence,
        kind: request.kind,
        action_digest_sha256: request.action_digest_sha256.clone(),
        requested_scope_ref: request.requested_scope_ref.clone(),
        display_summary_ref: request.display_summary_ref.clone(),
        request_observation_id: observation.observation_id,
        request_observation_sequence: observation.observation_sequence,
        request_lifecycle: request.lifecycle,
        request_revision: request.request_revision,
        policy_decision,
        available_actions: Vec::new(),
        redactions: vec![RedactedField {
            field_path: "harness_approval.native_routing_ref".to_owned(),
            reason_code: "ADAPTER_PRIVATE_ROUTING".to_owned(),
        }],
    };
    if !binding_complete {
        view.metadata
            .as_mut()
            .expect("metadata created")
            .safe_health_reason_code = Some("COLLABORATION_BINDING_PENDING".to_owned());
    }
    let view_payload = view.encode_to_vec();
    let frame = HarnessApprovalViewStreamFrame {
        kind: StreamFrameKind::Snapshot as i32,
        position: Some(position),
        snapshot: Some(view),
        reset_reason_code: None,
    };
    transaction.execute(
        "INSERT INTO harness_approval_views(approval_request_id,updated_sequence,view)
         VALUES(?1,?2,?3)
         ON CONFLICT(approval_request_id) DO UPDATE SET
           updated_sequence=excluded.updated_sequence,view=excluded.view",
        params![approval_id, sequence as i64, view_payload],
    )?;
    transaction.execute(
        "INSERT INTO harness_approval_frames(sequence,approval_request_id,frame)
         VALUES(?1,?2,?3)",
        params![sequence as i64, approval_id, frame.encode_to_vec()],
    )?;
    Ok(())
}

fn apply_access(
    view: &mut HarnessApprovalView,
    access: ApprovalViewAccess,
    health: ProjectionHealth,
) {
    view.available_actions.clear();
    if let Some(metadata) = view.metadata.as_mut() {
        metadata.health = health as i32;
        if health != ProjectionHealth::Ready {
            metadata.stale = true;
            metadata.safe_health_reason_code = Some("PROJECTION_NOT_READY".to_owned());
        }
    }
    if health != ProjectionHealth::Ready {
        return;
    }
    let binding_complete = !view.task_id.is_empty()
        && !view.run_id.is_empty()
        && !view.step_id.is_empty()
        && !view.attempt_id.is_empty()
        && !view.dispatch_id.is_empty()
        && view.fencing_token > 0;
    if access.can_decide
        && binding_complete
        && view.request_lifecycle == ApprovalRequestLifecycleKind::Open as i32
        && view.policy_decision.is_none()
    {
        view.available_actions.push(AvailableAction {
            kind: AvailableActionKind::DecideHarnessApproval as i32,
            owning_authority: "policy-decision-authority".to_owned(),
            derivation_rule_ref: DECIDE_RULE_REF.to_owned(),
            explicit_confirmation_required: true,
            reason_code: None,
        });
    }
}

fn projection_epoch(transaction: &Transaction<'_>) -> Result<String, ProjectionFailure> {
    transaction
        .query_row(
            "SELECT epoch FROM projection_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[allow(dead_code)]
fn _assert_path_is_scoped(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}
