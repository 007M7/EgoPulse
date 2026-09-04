-- Frozen pre-R9C Local Read Model schema.
--
-- This fixture is intentionally independent from the production SCHEMA_V*
-- constants. The R9C migration test must start from a real V3 shape instead
-- of creating V4 and deleting the new tables.
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

CREATE TABLE task_domain_projections (
  task_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;
CREATE TABLE artifact_object_projections (
  object_kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  PRIMARY KEY(object_kind,object_id)
) STRICT;
CREATE INDEX artifact_projection_task_idx
  ON artifact_object_projections(task_id,object_kind,object_id);
CREATE TABLE verification_result_projections (
  aggregate_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  verification_artifact_id TEXT,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  result BLOB NOT NULL
) STRICT;
CREATE UNIQUE INDEX verification_artifact_projection_idx
  ON verification_result_projections(verification_artifact_id)
  WHERE verification_artifact_id IS NOT NULL;
CREATE TABLE verdict_result_projections (
  founder_verdict_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  result BLOB NOT NULL
) STRICT;
CREATE TABLE task_views (
  task_id TEXT PRIMARY KEY,
  updated_sequence INTEGER NOT NULL CHECK (updated_sequence >= 1),
  view BLOB NOT NULL
) STRICT;
CREATE TABLE task_view_frames (
  sequence INTEGER NOT NULL,
  task_id TEXT NOT NULL,
  frame BLOB NOT NULL,
  PRIMARY KEY(sequence,task_id)
) STRICT;
CREATE TABLE evidence_graph_views (
  task_id TEXT NOT NULL,
  artifact_set_id TEXT NOT NULL,
  updated_sequence INTEGER NOT NULL CHECK (updated_sequence >= 1),
  view BLOB NOT NULL,
  PRIMARY KEY(task_id,artifact_set_id)
) STRICT;

ALTER TABLE projection_metadata
  ADD COLUMN retention_floor_sequence INTEGER NOT NULL DEFAULT 0
  CHECK (retention_floor_sequence >= 0 AND retention_floor_sequence <= current_sequence);
CREATE INDEX task_view_frames_entity_sequence_idx
  ON task_view_frames(task_id,sequence);
CREATE INDEX approval_view_frames_entity_sequence_idx
  ON harness_approval_frames(approval_request_id,sequence);
