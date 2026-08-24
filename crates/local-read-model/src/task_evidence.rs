use super::*;
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactCommandResult, ArtifactDescriptor, ArtifactSet, Claim, Evidence,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    EvidenceGraphView, TaskView, TaskViewStreamFrame,
};
use egopulse_domain_contracts::v01::egopulse::task::v1::{TaskEvent, TaskSnapshot, TaskStatus};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::VerdictCommandResult;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    VerificationArtifact, VerificationCommandResult,
};

const TASK_VIEW_CONTRACT_ID: &str = "egopulse.localapi.v1/TaskView";
const EVIDENCE_GRAPH_CONTRACT_ID: &str = "egopulse.localapi.v1/EvidenceGraphView";
const TASK_ACTION_RULE_REF: &str = "egopulse/local-read-model/task-actionable/v1";

#[derive(Clone, Debug)]
pub struct TaskProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub event: TaskEvent,
}

#[derive(Clone, Debug)]
pub struct ArtifactProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub result: ArtifactCommandResult,
}

#[derive(Clone, Debug)]
pub struct VerificationProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub result: VerificationCommandResult,
}

#[derive(Clone, Debug)]
pub struct VerdictProjectionInput {
    pub metadata: ProjectionMessageMetadata,
    pub result: VerdictCommandResult,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskViewAccess {
    pub can_read: bool,
    pub can_request_cancellation: bool,
    pub can_resume: bool,
    pub can_revise: bool,
    pub can_issue_founder_verdict: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvidenceGraphAccess {
    pub can_read: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskListFilter {
    pub statuses: Vec<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionApply {
    Committed {
        position: ProjectionPosition,
        changed_task_ids: Vec<String>,
    },
    Replay {
        position: ProjectionPosition,
    },
}

impl LocalReadModel {
    pub fn apply_task(
        &mut self,
        input: &TaskProjectionInput,
    ) -> Result<TaskProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.event.encode_to_vec())?;
        let snapshot = input
            .event
            .snapshot
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        if input.event.event_id != input.metadata.source_event_id
            || input.event.resulting_revision != input.metadata.source_revision
            || snapshot.task_id != input.event.task_id
            || snapshot.revision != input.metadata.source_revision
            || snapshot.task_id.trim().is_empty()
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let task_id = snapshot.task_id.clone();
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::Task, &input.metadata)? {
                return Ok(None);
            }
            if !upsert_task(tx, snapshot, &input.metadata)? {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            recompute_task_view(tx, &task_id, sequence, &input.metadata.projected_at)?;
            bind_inbox_sequence(tx, SourceDomain::Task, &input.metadata, sequence)?;
            Ok(Some((sequence, vec![task_id])))
        });
        self.finish_task_apply(result, &input.metadata.projected_at)
    }

    pub fn apply_artifact(
        &mut self,
        input: &ArtifactProjectionInput,
    ) -> Result<TaskProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.result.encode_to_vec())?;
        let event = input
            .result
            .event
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        if !input.result.committed
            || event.event_id != input.metadata.source_event_id
            || event.aggregate_revision != input.metadata.source_revision
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let object = artifact_object(&input.result, event)?;
        let task_id = object.task_id.clone();
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::Artifact, &input.metadata)? {
                return Ok(None);
            }
            if !upsert_artifact_object(tx, &object, &input.metadata)? {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            recompute_task_view(tx, &task_id, sequence, &input.metadata.projected_at)?;
            recompute_evidence_graphs(tx, &task_id, sequence, &input.metadata.projected_at)?;
            bind_inbox_sequence(tx, SourceDomain::Artifact, &input.metadata, sequence)?;
            Ok(Some((sequence, vec![task_id])))
        });
        self.finish_task_apply(result, &input.metadata.projected_at)
    }

    pub fn apply_verification(
        &mut self,
        input: &VerificationProjectionInput,
    ) -> Result<TaskProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.result.encode_to_vec())?;
        let event = input
            .result
            .event
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        if !input.result.committed
            || event.event_id != input.metadata.source_event_id
            || event.aggregate_revision != input.metadata.source_revision
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let task_id = verification_task_id(&input.result);
        let artifact_id = input
            .result
            .artifact
            .as_ref()
            .map(|value| value.verification_artifact_id.clone());
        let aggregate_id = event.aggregate_id.clone();
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::Verification, &input.metadata)? {
                return Ok(None);
            }
            if !upsert_verification(
                tx,
                &aggregate_id,
                &task_id,
                artifact_id.as_deref(),
                &input.result,
                &input.metadata,
            )? {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            let mut changed = Vec::new();
            if !task_id.is_empty() {
                recompute_task_view(tx, &task_id, sequence, &input.metadata.projected_at)?;
                changed.push(task_id.clone());
            }
            bind_inbox_sequence(tx, SourceDomain::Verification, &input.metadata, sequence)?;
            Ok(Some((sequence, changed)))
        });
        self.finish_task_apply(result, &input.metadata.projected_at)
    }

    pub fn apply_verdict(
        &mut self,
        input: &VerdictProjectionInput,
    ) -> Result<TaskProjectionApply, ProjectionFailure> {
        validate_metadata(&input.metadata, &input.result.encode_to_vec())?;
        let event = input
            .result
            .event
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let verdict = input
            .result
            .verdict
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let state = input
            .result
            .state
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        let scope = verdict
            .scope
            .as_ref()
            .ok_or(ProjectionFailure::InvalidMessage)?;
        if !input.result.committed
            || event.event_id != input.metadata.source_event_id
            || event.resulting_state_revision != input.metadata.source_revision
            || state.revision != input.metadata.source_revision
            || event.founder_verdict_id != verdict.founder_verdict_id
            || state.founder_verdict_id != verdict.founder_verdict_id
            || scope.task_id.trim().is_empty()
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let task_id = scope.task_id.clone();
        let verdict_id = verdict.founder_verdict_id.clone();
        let result = self.apply_transaction(|tx| {
            if register_inbox(tx, SourceDomain::FounderVerdict, &input.metadata)? {
                return Ok(None);
            }
            if !upsert_verdict(tx, &verdict_id, &task_id, &input.result, &input.metadata)? {
                return Ok(None);
            }
            let sequence = next_sequence(tx)?;
            recompute_task_view(tx, &task_id, sequence, &input.metadata.projected_at)?;
            bind_inbox_sequence(tx, SourceDomain::FounderVerdict, &input.metadata, sequence)?;
            Ok(Some((sequence, vec![task_id])))
        });
        self.finish_task_apply(result, &input.metadata.projected_at)
    }

    pub fn get_task_view(
        &self,
        task_id: &str,
        access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let health = self.health()?;
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT view FROM task_views WHERE task_id=?1",
                [task_id],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|value| {
                let mut view = TaskView::decode(value.as_slice())?;
                apply_task_access(&mut view, access, health);
                Ok(view)
            })
            .transpose()
    }

    pub fn list_task_views(
        &self,
        filter: &TaskListFilter,
        access: TaskViewAccess,
    ) -> Result<Vec<TaskView>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let health = self.health()?;
        let mut statement = self
            .connection
            .prepare("SELECT view FROM task_views ORDER BY updated_sequence DESC,task_id")?;
        let payloads = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut views = Vec::new();
        for payload in payloads {
            let mut view = TaskView::decode(payload.as_slice())?;
            if !filter.statuses.is_empty()
                && view
                    .task
                    .as_ref()
                    .is_none_or(|task| !filter.statuses.contains(&task.status))
            {
                continue;
            }
            apply_task_access(&mut view, access, health);
            views.push(view);
        }
        Ok(views)
    }

    pub fn task_frames_after(
        &self,
        after: &ProjectionPosition,
        filter: &TaskListFilter,
        task_ids: &[String],
        access: TaskViewAccess,
    ) -> Result<Vec<TaskViewStreamFrame>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let current = self.position()?;
        let health = self.health()?;
        if after.epoch != current.epoch
            || after.sequence > current.sequence
            || health != ProjectionHealth::Ready
        {
            return Ok(vec![TaskViewStreamFrame {
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
            "SELECT frame FROM task_view_frames WHERE sequence>?1 ORDER BY sequence,task_id",
        )?;
        let payloads = statement
            .query_map([after.sequence as i64], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut frames = Vec::new();
        for payload in payloads {
            let mut frame = TaskViewStreamFrame::decode(payload.as_slice())?;
            let Some(view) = frame.snapshot.as_mut() else {
                continue;
            };
            let Some(task) = view.task.as_ref() else {
                return Err(ProjectionFailure::IntegrityFailure);
            };
            if (!task_ids.is_empty() && !task_ids.contains(&task.task_id))
                || (!filter.statuses.is_empty() && !filter.statuses.contains(&task.status))
            {
                continue;
            }
            apply_task_access(view, access, health);
            frames.push(frame);
        }
        Ok(frames)
    }

    pub fn get_evidence_graph(
        &self,
        task_id: &str,
        artifact_set_id: &str,
        access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ProjectionFailure> {
        if !access.can_read {
            return Err(ProjectionFailure::PermissionDenied);
        }
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT view FROM evidence_graph_views WHERE task_id=?1 AND artifact_set_id=?2",
                params![task_id, artifact_set_id],
                |row| row.get(0),
            )
            .optional()?;
        let health = self.health()?;
        payload
            .map(|value| {
                let mut view = EvidenceGraphView::decode(value.as_slice())?;
                if let Some(metadata) = view.metadata.as_mut() {
                    metadata.health = health as i32;
                    if health != ProjectionHealth::Ready {
                        metadata.stale = true;
                        metadata.safe_health_reason_code = Some("PROJECTION_NOT_READY".to_owned());
                    }
                }
                Ok(view)
            })
            .transpose()
    }

    pub fn has_projected_source(
        &self,
        required: &SourceRevision,
    ) -> Result<bool, ProjectionFailure> {
        let domain = SourceDomain::try_from(required.domain)
            .map_err(|_| ProjectionFailure::InvalidMessage)?;
        if domain == SourceDomain::Unspecified
            || required.aggregate_id.trim().is_empty()
            || required.revision == 0
            || required.last_event_id.trim().is_empty()
        {
            return Err(ProjectionFailure::InvalidMessage);
        }
        let event_count: i64 = self.connection.query_row(
            "SELECT count(*) FROM projection_inbox
             WHERE source_domain=?1 AND source_event_id=?2 AND source_revision=?3
               AND committed_sequence IS NOT NULL",
            params![
                domain as i32,
                required.last_event_id,
                required.revision as i64
            ],
            |row| row.get(0),
        )?;
        if event_count == 0 {
            return Ok(false);
        }
        projected_aggregate_head_at_least(&self.connection, domain, required)
    }

    fn finish_task_apply(
        &mut self,
        result: Result<Option<(u64, Vec<String>)>, ProjectionFailure>,
        projected_at: &Timestamp,
    ) -> Result<TaskProjectionApply, ProjectionFailure> {
        match result {
            Ok(Some((sequence, ids))) => Ok(TaskProjectionApply::Committed {
                position: self.position_at(sequence, projected_at),
                changed_task_ids: ids,
            }),
            Ok(None) => Ok(TaskProjectionApply::Replay {
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
}

fn projected_aggregate_head_at_least(
    connection: &Connection,
    domain: SourceDomain,
    required: &SourceRevision,
) -> Result<bool, ProjectionFailure> {
    let simple_table = match domain {
        SourceDomain::Task => Some(("task_domain_projections", "task_id")),
        SourceDomain::Collaboration => Some(("collaboration_projections", "run_id")),
        SourceDomain::Artifact => Some(("artifact_object_projections", "object_id")),
        SourceDomain::Verification => Some(("verification_result_projections", "aggregate_id")),
        SourceDomain::FounderVerdict => Some(("verdict_result_projections", "founder_verdict_id")),
        SourceDomain::HarnessAdapter => {
            Some(("approval_request_projections", "approval_request_id"))
        }
        SourceDomain::PolicyDecision => None,
        SourceDomain::Unspecified => return Err(ProjectionFailure::InvalidMessage),
    };
    if let Some((table, id_column)) = simple_table {
        let query =
            format!("SELECT count(*) FROM {table} WHERE {id_column}=?1 AND source_revision>=?2");
        let count: i64 = connection.query_row(
            &query,
            params![required.aggregate_id, required.revision as i64],
            |row| row.get(0),
        )?;
        return Ok(count > 0);
    }

    let mut statement = connection
        .prepare("SELECT result FROM policy_decision_projections WHERE source_revision>=?1")?;
    let payloads = statement
        .query_map([required.revision as i64], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for payload in payloads {
        let result = PolicyDecisionCommandResult::decode(payload.as_slice())?;
        if result
            .decision_record
            .as_ref()
            .is_some_and(|record| record.authority_decision_ref == required.aggregate_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn recompute_task_for_run(
    tx: &Transaction<'_>,
    run_id: &str,
    sequence: u64,
    projected_at: &Timestamp,
) -> Result<(), ProjectionFailure> {
    let task_id: Option<String> = tx
        .query_row(
            "SELECT snapshot FROM collaboration_projections WHERE run_id=?1",
            [run_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|payload| CollaborationSnapshot::decode(payload.as_slice()))
        .transpose()?
        .and_then(|snapshot| snapshot.run.map(|run| run.task_id));
    if let Some(task_id) = task_id {
        recompute_task_view(tx, &task_id, sequence, projected_at)?;
    }
    Ok(())
}

struct ArtifactObject {
    kind: &'static str,
    id: String,
    task_id: String,
    revision: u64,
    snapshot: Vec<u8>,
}

fn artifact_object(
    result: &ArtifactCommandResult,
    event: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactEvent,
) -> Result<ArtifactObject, ProjectionFailure> {
    let object = if let Some(value) = result.artifact.as_ref() {
        ArtifactObject {
            kind: "artifact",
            id: value.artifact_id.clone(),
            task_id: value
                .provenance
                .as_ref()
                .and_then(|item| item.lineage.as_ref())
                .map(|lineage| lineage.task_id.clone())
                .unwrap_or_default(),
            revision: value.revision,
            snapshot: value.encode_to_vec(),
        }
    } else if let Some(value) = result.claim.as_ref() {
        ArtifactObject {
            kind: "claim",
            id: value.claim_id.clone(),
            task_id: value
                .lineage
                .as_ref()
                .map(|lineage| lineage.task_id.clone())
                .unwrap_or_default(),
            revision: value.revision,
            snapshot: value.encode_to_vec(),
        }
    } else if let Some(value) = result.evidence.as_ref() {
        ArtifactObject {
            kind: "evidence",
            id: value.evidence_id.clone(),
            task_id: value
                .lineage
                .as_ref()
                .map(|lineage| lineage.task_id.clone())
                .unwrap_or_default(),
            revision: value.revision,
            snapshot: value.encode_to_vec(),
        }
    } else if let Some(value) = result.artifact_set.as_ref() {
        ArtifactObject {
            kind: "artifact_set",
            id: value.artifact_set_id.clone(),
            task_id: value
                .lineage
                .as_ref()
                .map(|lineage| lineage.task_id.clone())
                .unwrap_or_default(),
            revision: value.revision,
            snapshot: value.encode_to_vec(),
        }
    } else if let Some(value) = result.return_handoff.as_ref() {
        ArtifactObject {
            kind: "return_handoff",
            id: value.return_handoff_id.clone(),
            task_id: value
                .lineage
                .as_ref()
                .map(|lineage| lineage.task_id.clone())
                .unwrap_or_default(),
            revision: value.revision,
            snapshot: value.encode_to_vec(),
        }
    } else {
        return Err(ProjectionFailure::InvalidMessage);
    };
    if object.id.trim().is_empty()
        || object.task_id.trim().is_empty()
        || object.id != event.aggregate_id
        || object.revision != event.aggregate_revision
    {
        return Err(ProjectionFailure::InvalidMessage);
    }
    Ok(object)
}

fn upsert_task(
    tx: &Transaction<'_>,
    snapshot: &TaskSnapshot,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
    upsert_revisioned(
        tx,
        "task_domain_projections",
        "task_id",
        &snapshot.task_id,
        metadata,
        || {
            tx.execute(
                "INSERT INTO task_domain_projections(
                   task_id,source_event_id,source_revision,payload_digest_sha256,snapshot
                 ) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(task_id) DO UPDATE SET source_event_id=excluded.source_event_id,
                   source_revision=excluded.source_revision,
                   payload_digest_sha256=excluded.payload_digest_sha256,snapshot=excluded.snapshot",
                params![
                    snapshot.task_id,
                    metadata.source_event_id,
                    metadata.source_revision as i64,
                    metadata.payload_digest_sha256,
                    snapshot.encode_to_vec()
                ],
            )?;
            Ok(())
        },
    )
}

fn upsert_artifact_object(
    tx: &Transaction<'_>,
    object: &ArtifactObject,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
    let existing: Option<(i64, String)> = tx
        .query_row(
            "SELECT source_revision,payload_digest_sha256 FROM artifact_object_projections
             WHERE object_kind=?1 AND object_id=?2",
            params![object.kind, object.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if !revision_change_allowed(tx, existing, metadata)? {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO artifact_object_projections(
           object_kind,object_id,task_id,source_event_id,source_revision,
           payload_digest_sha256,snapshot
         ) VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(object_kind,object_id) DO UPDATE SET task_id=excluded.task_id,
           source_event_id=excluded.source_event_id,source_revision=excluded.source_revision,
           payload_digest_sha256=excluded.payload_digest_sha256,snapshot=excluded.snapshot",
        params![
            object.kind,
            object.id,
            object.task_id,
            metadata.source_event_id,
            metadata.source_revision as i64,
            metadata.payload_digest_sha256,
            object.snapshot
        ],
    )?;
    Ok(true)
}

fn upsert_verification(
    tx: &Transaction<'_>,
    aggregate_id: &str,
    task_id: &str,
    artifact_id: Option<&str>,
    result: &VerificationCommandResult,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
    let existing: Option<(i64, String)> = tx
        .query_row(
            "SELECT source_revision,payload_digest_sha256 FROM verification_result_projections
             WHERE aggregate_id=?1",
            [aggregate_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if !revision_change_allowed(tx, existing, metadata)? {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO verification_result_projections(
           aggregate_id,task_id,verification_artifact_id,source_event_id,source_revision,
           payload_digest_sha256,result
         ) VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(aggregate_id) DO UPDATE SET task_id=excluded.task_id,
           verification_artifact_id=excluded.verification_artifact_id,
           source_event_id=excluded.source_event_id,source_revision=excluded.source_revision,
           payload_digest_sha256=excluded.payload_digest_sha256,result=excluded.result",
        params![
            aggregate_id,
            task_id,
            artifact_id,
            metadata.source_event_id,
            metadata.source_revision as i64,
            metadata.payload_digest_sha256,
            result.encode_to_vec()
        ],
    )?;
    Ok(true)
}

fn upsert_verdict(
    tx: &Transaction<'_>,
    verdict_id: &str,
    task_id: &str,
    result: &VerdictCommandResult,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
    let existing: Option<(i64, String)> = tx
        .query_row(
            "SELECT source_revision,payload_digest_sha256 FROM verdict_result_projections
             WHERE founder_verdict_id=?1",
            [verdict_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if !revision_change_allowed(tx, existing, metadata)? {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO verdict_result_projections(
           founder_verdict_id,task_id,source_event_id,source_revision,
           payload_digest_sha256,result
         ) VALUES(?1,?2,?3,?4,?5,?6)
         ON CONFLICT(founder_verdict_id) DO UPDATE SET task_id=excluded.task_id,
           source_event_id=excluded.source_event_id,source_revision=excluded.source_revision,
           payload_digest_sha256=excluded.payload_digest_sha256,result=excluded.result",
        params![
            verdict_id,
            task_id,
            metadata.source_event_id,
            metadata.source_revision as i64,
            metadata.payload_digest_sha256,
            result.encode_to_vec()
        ],
    )?;
    Ok(true)
}

fn upsert_revisioned(
    tx: &Transaction<'_>,
    table: &str,
    id_column: &str,
    id: &str,
    metadata: &ProjectionMessageMetadata,
    write: impl FnOnce() -> Result<(), ProjectionFailure>,
) -> Result<bool, ProjectionFailure> {
    let sql =
        format!("SELECT source_revision,payload_digest_sha256 FROM {table} WHERE {id_column}=?1");
    let existing: Option<(i64, String)> = tx
        .query_row(&sql, [id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    if !revision_change_allowed(tx, existing, metadata)? {
        return Ok(false);
    }
    write()?;
    Ok(true)
}

fn revision_change_allowed(
    tx: &Transaction<'_>,
    existing: Option<(i64, String)>,
    metadata: &ProjectionMessageMetadata,
) -> Result<bool, ProjectionFailure> {
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
        validate_initial_projection(tx, metadata)?;
    }
    Ok(true)
}

fn verification_task_id(result: &VerificationCommandResult) -> String {
    result
        .artifact
        .as_ref()
        .and_then(|value| value.binding.as_ref())
        .and_then(|binding| binding.lineage.as_ref())
        .or_else(|| {
            result
                .request
                .as_ref()
                .and_then(|value| value.binding.as_ref())
                .and_then(|binding| binding.lineage.as_ref())
        })
        .map(|lineage| lineage.task_id.clone())
        .unwrap_or_default()
}

#[allow(clippy::too_many_lines)]
fn recompute_task_view(
    tx: &Transaction<'_>,
    task_id: &str,
    sequence: u64,
    projected_at: &Timestamp,
) -> Result<(), ProjectionFailure> {
    let task_row: Option<(u64, String, Vec<u8>)> = tx
        .query_row(
            "SELECT source_revision,source_event_id,snapshot FROM task_domain_projections
             WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((task_revision, task_event, task_payload)) = task_row else {
        return Ok(());
    };
    let task = TaskSnapshot::decode(task_payload.as_slice())?;
    if task.task_id != task_id || task.revision != task_revision {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    let mut source_revisions = vec![SourceRevision {
        domain: SourceDomain::Task as i32,
        aggregate_id: task_id.to_owned(),
        revision: task_revision,
        last_event_id: task_event,
    }];
    let mut dependency_pending = false;

    let collaboration = if let Some(run_id) = task.current_run_id.as_deref() {
        let row: Option<(u64, String, Vec<u8>)> = tx
            .query_row(
                "SELECT source_revision,source_event_id,snapshot FROM collaboration_projections
                 WHERE run_id=?1",
                [run_id],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((revision, event_id, payload)) = row {
            let snapshot = CollaborationSnapshot::decode(payload.as_slice())?;
            let run = snapshot
                .run
                .as_ref()
                .ok_or(ProjectionFailure::IntegrityFailure)?;
            if run.run_id != run_id
                || run.task_id != task.task_id
                || run.work_revision != task.work_revision
            {
                return Err(ProjectionFailure::IntegrityFailure);
            }
            source_revisions.push(SourceRevision {
                domain: SourceDomain::Collaboration as i32,
                aggregate_id: run_id.to_owned(),
                revision,
                last_event_id: event_id,
            });
            Some(snapshot)
        } else {
            dependency_pending = true;
            None
        }
    } else {
        None
    };

    let artifact_set = load_artifact_set(tx, task.artifact_set_id.as_deref(), task_id)?;
    if let Some((revision, event_id, value)) = artifact_set.as_ref() {
        source_revisions.push(SourceRevision {
            domain: SourceDomain::Artifact as i32,
            aggregate_id: value.artifact_set_id.clone(),
            revision: *revision,
            last_event_id: event_id.clone(),
        });
        if !artifact_set_members_complete(tx, value, task_id)? {
            dependency_pending = true;
        }
    } else if task.artifact_set_id.is_some() {
        dependency_pending = true;
    }

    let verification = load_verification(
        tx,
        task.verification_artifact_id.as_deref(),
        task_id,
        task.artifact_set_id.as_deref(),
    )?;
    if let Some((revision, event_id, value)) = verification.as_ref() {
        source_revisions.push(SourceRevision {
            domain: SourceDomain::Verification as i32,
            aggregate_id: value.verification_artifact_id.clone(),
            revision: *revision,
            last_event_id: event_id.clone(),
        });
    } else if task.verification_artifact_id.is_some() {
        dependency_pending = true;
    }

    let verdict = load_verdict(tx, task.founder_verdict_id.as_deref(), &task)?;
    if let Some((revision, event_id, result)) = verdict.as_ref() {
        source_revisions.push(SourceRevision {
            domain: SourceDomain::FounderVerdict as i32,
            aggregate_id: result
                .verdict
                .as_ref()
                .map(|value| value.founder_verdict_id.clone())
                .unwrap_or_default(),
            revision: *revision,
            last_event_id: event_id.clone(),
        });
    } else if task.founder_verdict_id.is_some() {
        dependency_pending = true;
    }
    source_revisions.sort_by(|left, right| {
        left.domain
            .cmp(&right.domain)
            .then_with(|| left.aggregate_id.cmp(&right.aggregate_id))
    });
    let position = ProjectionPosition {
        epoch: projection_epoch(tx)?,
        sequence,
        projected_at: Some(*projected_at),
    };
    let view = TaskView {
        metadata: Some(ProjectionMetadata {
            schema_ref: Some(ContractReference {
                contract_id: TASK_VIEW_CONTRACT_ID.to_owned(),
                version: VIEW_CONTRACT_VERSION.to_owned(),
                sha256: VIEW_CONTRACT_SHA256.to_owned(),
            }),
            position: Some(position.clone()),
            source_revisions,
            health: ProjectionHealth::Ready as i32,
            stale: dependency_pending,
            safe_health_reason_code: dependency_pending
                .then(|| "DEPENDENCY_PROJECTION_PENDING".to_owned()),
        }),
        task: Some(task),
        collaboration,
        artifact_set: artifact_set.map(|(_, _, value)| value),
        verification: verification.map(|(_, _, value)| value),
        founder_verdict: verdict
            .as_ref()
            .and_then(|(_, _, result)| result.verdict.clone()),
        founder_verdict_state: verdict.and_then(|(_, _, result)| result.state),
        available_actions: Vec::new(),
        redactions: Vec::new(),
    };
    let frame = TaskViewStreamFrame {
        kind: StreamFrameKind::Snapshot as i32,
        position: Some(position),
        snapshot: Some(view.clone()),
        reset_reason_code: None,
    };
    tx.execute(
        "INSERT INTO task_views(task_id,updated_sequence,view) VALUES(?1,?2,?3)
         ON CONFLICT(task_id) DO UPDATE SET updated_sequence=excluded.updated_sequence,
           view=excluded.view",
        params![task_id, sequence as i64, view.encode_to_vec()],
    )?;
    tx.execute(
        "INSERT INTO task_view_frames(sequence,task_id,frame) VALUES(?1,?2,?3)",
        params![sequence as i64, task_id, frame.encode_to_vec()],
    )?;
    recompute_evidence_graphs(tx, task_id, sequence, projected_at)?;
    Ok(())
}

fn load_artifact_set(
    tx: &Transaction<'_>,
    artifact_set_id: Option<&str>,
    task_id: &str,
) -> Result<Option<(u64, String, ArtifactSet)>, ProjectionFailure> {
    let Some(id) = artifact_set_id else {
        return Ok(None);
    };
    let row: Option<(u64, String, Vec<u8>, String)> = tx
        .query_row(
            "SELECT source_revision,source_event_id,snapshot,task_id
             FROM artifact_object_projections WHERE object_kind='artifact_set' AND object_id=?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(revision, event, payload, owner_task)| {
        let value = ArtifactSet::decode(payload.as_slice())?;
        if value.artifact_set_id != id || owner_task != task_id || value.revision != revision {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        Ok((revision, event, value))
    })
    .transpose()
}

fn load_verification(
    tx: &Transaction<'_>,
    artifact_id: Option<&str>,
    task_id: &str,
    artifact_set_id: Option<&str>,
) -> Result<Option<(u64, String, VerificationArtifact)>, ProjectionFailure> {
    let Some(id) = artifact_id else {
        return Ok(None);
    };
    let row: Option<(u64, String, Vec<u8>, String)> = tx
        .query_row(
            "SELECT source_revision,source_event_id,result,task_id
             FROM verification_result_projections WHERE verification_artifact_id=?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(revision, event, payload, owner_task)| {
        let result = VerificationCommandResult::decode(payload.as_slice())?;
        let value = result.artifact.ok_or(ProjectionFailure::IntegrityFailure)?;
        let binding = value
            .binding
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        if value.verification_artifact_id != id
            || owner_task != task_id
            || binding.artifact_set_id != artifact_set_id.unwrap_or_default()
        {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        Ok((revision, event, value))
    })
    .transpose()
}

fn load_verdict(
    tx: &Transaction<'_>,
    verdict_id: Option<&str>,
    task: &TaskSnapshot,
) -> Result<Option<(u64, String, VerdictCommandResult)>, ProjectionFailure> {
    let Some(id) = verdict_id else {
        return Ok(None);
    };
    let row: Option<(u64, String, Vec<u8>, String)> = tx
        .query_row(
            "SELECT source_revision,source_event_id,result,task_id
             FROM verdict_result_projections WHERE founder_verdict_id=?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(revision, event, payload, owner_task)| {
        let result = VerdictCommandResult::decode(payload.as_slice())?;
        let verdict = result
            .verdict
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        let scope = verdict
            .scope
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        let state = result
            .state
            .as_ref()
            .ok_or(ProjectionFailure::IntegrityFailure)?;
        if verdict.founder_verdict_id != id
            || state.founder_verdict_id != id
            || state.revision != revision
            || owner_task != task.task_id
            || scope.task_id != task.task_id
            || scope.work_revision != task.work_revision
            || scope.artifact_set_id != task.artifact_set_id.as_deref().unwrap_or_default()
            || scope.verification_artifact_id
                != task.verification_artifact_id.as_deref().unwrap_or_default()
        {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        Ok((revision, event, result))
    })
    .transpose()
}

fn recompute_evidence_graphs(
    tx: &Transaction<'_>,
    task_id: &str,
    sequence: u64,
    projected_at: &Timestamp,
) -> Result<(), ProjectionFailure> {
    let mut statement = tx.prepare(
        "SELECT object_id FROM artifact_object_projections
         WHERE object_kind='artifact_set' AND task_id=?1 ORDER BY object_id",
    )?;
    let ids = statement
        .query_map([task_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for id in ids {
        recompute_evidence_graph(tx, task_id, &id, sequence, projected_at)?;
    }
    Ok(())
}

fn recompute_evidence_graph(
    tx: &Transaction<'_>,
    task_id: &str,
    artifact_set_id: &str,
    sequence: u64,
    projected_at: &Timestamp,
) -> Result<(), ProjectionFailure> {
    let Some((set_revision, set_event, set)) =
        load_artifact_set(tx, Some(artifact_set_id), task_id)?
    else {
        return Ok(());
    };
    let mut sources = vec![SourceRevision {
        domain: SourceDomain::Artifact as i32,
        aggregate_id: artifact_set_id.to_owned(),
        revision: set_revision,
        last_event_id: set_event,
    }];
    let mut artifacts = Vec::new();
    let mut dependency_pending = false;
    for id in &set.artifact_ids {
        if let Some((revision, event, payload)) = load_artifact_member(tx, "artifact", id, task_id)?
        {
            let value = ArtifactDescriptor::decode(payload.as_slice())?;
            validate_artifact_member(&value, id, revision, task_id)?;
            artifacts.push(value);
            sources.push(SourceRevision {
                domain: SourceDomain::Artifact as i32,
                aggregate_id: id.clone(),
                revision,
                last_event_id: event,
            });
        } else {
            dependency_pending = true;
        }
    }
    let mut claims = Vec::new();
    for id in &set.claim_ids {
        if let Some((revision, event, payload)) = load_artifact_member(tx, "claim", id, task_id)? {
            let value = Claim::decode(payload.as_slice())?;
            validate_claim_member(&value, id, revision, task_id)?;
            claims.push(value);
            sources.push(SourceRevision {
                domain: SourceDomain::Artifact as i32,
                aggregate_id: id.clone(),
                revision,
                last_event_id: event,
            });
        } else {
            dependency_pending = true;
        }
    }
    let mut evidence = Vec::new();
    for id in &set.evidence_ids {
        if let Some((revision, event, payload)) = load_artifact_member(tx, "evidence", id, task_id)?
        {
            let value = Evidence::decode(payload.as_slice())?;
            validate_evidence_member(&value, id, revision, task_id)?;
            evidence.push(value);
            sources.push(SourceRevision {
                domain: SourceDomain::Artifact as i32,
                aggregate_id: id.clone(),
                revision,
                last_event_id: event,
            });
        } else {
            dependency_pending = true;
        }
    }
    if dependency_pending {
        artifacts.clear();
        claims.clear();
        evidence.clear();
    }
    let graph = EvidenceGraphView {
        metadata: Some(ProjectionMetadata {
            schema_ref: Some(ContractReference {
                contract_id: EVIDENCE_GRAPH_CONTRACT_ID.to_owned(),
                version: VIEW_CONTRACT_VERSION.to_owned(),
                sha256: VIEW_CONTRACT_SHA256.to_owned(),
            }),
            position: Some(ProjectionPosition {
                epoch: projection_epoch(tx)?,
                sequence,
                projected_at: Some(*projected_at),
            }),
            source_revisions: sources,
            health: ProjectionHealth::Ready as i32,
            stale: dependency_pending,
            safe_health_reason_code: dependency_pending
                .then(|| "DEPENDENCY_PROJECTION_PENDING".to_owned()),
        }),
        task_id: task_id.to_owned(),
        artifact_set_id: artifact_set_id.to_owned(),
        artifacts,
        claims,
        evidence,
        redactions: Vec::new(),
    };
    tx.execute(
        "INSERT INTO evidence_graph_views(task_id,artifact_set_id,updated_sequence,view)
         VALUES(?1,?2,?3,?4)
         ON CONFLICT(task_id,artifact_set_id) DO UPDATE SET
           updated_sequence=excluded.updated_sequence,view=excluded.view",
        params![
            task_id,
            artifact_set_id,
            sequence as i64,
            graph.encode_to_vec()
        ],
    )?;
    Ok(())
}

fn artifact_set_members_complete(
    tx: &Transaction<'_>,
    set: &ArtifactSet,
    task_id: &str,
) -> Result<bool, ProjectionFailure> {
    for (kind, ids) in [
        ("artifact", &set.artifact_ids),
        ("claim", &set.claim_ids),
        ("evidence", &set.evidence_ids),
    ] {
        for id in ids {
            if load_artifact_member(tx, kind, id, task_id)?.is_none() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn validate_artifact_member(
    value: &ArtifactDescriptor,
    id: &str,
    revision: u64,
    task_id: &str,
) -> Result<(), ProjectionFailure> {
    let owner = value
        .provenance
        .as_ref()
        .and_then(|item| item.lineage.as_ref())
        .map(|lineage| lineage.task_id.as_str());
    if value.artifact_id != id || value.revision != revision || owner != Some(task_id) {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    Ok(())
}

fn validate_claim_member(
    value: &Claim,
    id: &str,
    revision: u64,
    task_id: &str,
) -> Result<(), ProjectionFailure> {
    let owner = value
        .lineage
        .as_ref()
        .map(|lineage| lineage.task_id.as_str());
    if value.claim_id != id || value.revision != revision || owner != Some(task_id) {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    Ok(())
}

fn validate_evidence_member(
    value: &Evidence,
    id: &str,
    revision: u64,
    task_id: &str,
) -> Result<(), ProjectionFailure> {
    let owner = value
        .lineage
        .as_ref()
        .map(|lineage| lineage.task_id.as_str());
    if value.evidence_id != id || value.revision != revision || owner != Some(task_id) {
        return Err(ProjectionFailure::IntegrityFailure);
    }
    Ok(())
}

fn load_artifact_member(
    tx: &Transaction<'_>,
    kind: &str,
    id: &str,
    task_id: &str,
) -> Result<Option<(u64, String, Vec<u8>)>, ProjectionFailure> {
    let row: Option<(u64, String, Vec<u8>, String)> = tx
        .query_row(
            "SELECT source_revision,source_event_id,snapshot,task_id
             FROM artifact_object_projections WHERE object_kind=?1 AND object_id=?2",
            params![kind, id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(revision, event, payload, owner_task)| {
        if owner_task != task_id {
            return Err(ProjectionFailure::IntegrityFailure);
        }
        Ok((revision, event, payload))
    })
    .transpose()
}

fn apply_task_access(view: &mut TaskView, access: TaskViewAccess, health: ProjectionHealth) {
    view.available_actions.clear();
    let Some(metadata) = view.metadata.as_mut() else {
        return;
    };
    metadata.health = health as i32;
    if health != ProjectionHealth::Ready {
        metadata.stale = true;
        metadata.safe_health_reason_code = Some("PROJECTION_NOT_READY".to_owned());
        return;
    }
    if metadata.stale {
        return;
    }
    let Some(task) = view.task.as_ref() else {
        metadata.stale = true;
        metadata.safe_health_reason_code = Some("TASK_PROJECTION_INVALID".to_owned());
        return;
    };
    let status = TaskStatus::try_from(task.status).unwrap_or(TaskStatus::Unspecified);
    if access.can_request_cancellation
        && matches!(
            status,
            TaskStatus::Active
                | TaskStatus::VerificationPending
                | TaskStatus::VerdictPending
                | TaskStatus::CancellationPending
        )
    {
        view.available_actions.push(action(
            AvailableActionKind::RequestCancellation,
            "TaskAuthority",
            true,
        ));
    }
    if access.can_resume && status == TaskStatus::Held {
        view.available_actions.push(action(
            AvailableActionKind::ResumeTask,
            "TaskAuthority",
            true,
        ));
    }
    if access.can_revise && status == TaskStatus::Rework {
        view.available_actions.push(action(
            AvailableActionKind::ReviseTask,
            "TaskAuthority",
            true,
        ));
    }
    if access.can_issue_founder_verdict && status == TaskStatus::VerdictPending {
        view.available_actions.push(action(
            AvailableActionKind::SubmitFounderVerdict,
            "FounderVerdictAuthority",
            true,
        ));
    }
}

fn action(kind: AvailableActionKind, owner: &str, confirm: bool) -> AvailableAction {
    AvailableAction {
        kind: kind as i32,
        owning_authority: owner.to_owned(),
        derivation_rule_ref: TASK_ACTION_RULE_REF.to_owned(),
        explicit_confirmation_required: confirm,
        reason_code: None,
    }
}
