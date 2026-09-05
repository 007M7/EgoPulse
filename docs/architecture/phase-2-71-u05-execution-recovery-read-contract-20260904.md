# U-05a execution and recovery read-contract evidence

- Date: 2026-09-04
- Scope: shared Rust read-only governed Task execution and recovery facts
- Status: locally verified
- Parent flow: U-05 user-readable execution and recovery review

## Outcome

U-05a adds a shared `client-operations` read contract for reviewing governed
Task, Run, Step and Attempt state. It reads the existing Task projection and
watch stream through the authenticated `ClientAttachment`; it does not expose
a resume, retry, recover or other mutation operation.

The public projection is deliberately smaller than `TaskView`. It contains
only safe identity and state facts:

- Task identity, revision, typed status, optional Authority-recorded resume
  status and classified hold reason;
- Run identity, revision, typed status, work revision and classified hold
  reason;
- ordered Step identities, revisions, typed statuses, safe hold reasons and
  current Attempt identity;
- ordered Attempt identities, revisions, numbers, typed statuses, recovery
  classes, safe hold reasons, last Harness sequence and a
  checkpoint-reference-recorded boolean; and
- projection epoch/sequence, health, stale state and classified safe reason.

Hold reasons are represented only by the closed `GovernedHoldReason` enum:
CancellationOutcomeUnknown, CompensationRequired, ManualRecoveryRequired,
IrreversibleOutcomeUnknown or Unclassified. An absent reason remains absent;
any other raw system value maps to Unclassified and is never copied into the
safe DTO or its debug representation.

Projection reasons are similarly represented only by the closed
`GovernedProjectionReason` enum: DependencyProjectionPending,
ProjectionNotReady, TaskProjectionInvalid or Unclassified. Unknown raw reason
text is not retained. `resume_status=UNSPECIFIED` is represented as absent;
known non-unspecified values are preserved and unknown enum values fail
closed. No resume value or hold reason is synthesized when Authority did not
record one.

`checkpoint_reference_recorded` says only that the Attempt snapshot contains
a checkpoint reference. It does not assert that checkpoint contents are
readable, intact, compatible or sufficient for recovery.

The projection does not retain or expose raw `TaskView`, metadata blobs,
workspace or Harness references, capability profiles, dispatch identities or
fingerprints, Harness sessions, leases, checkpoint identities, artifact or
evidence payloads, Provider/model data, or Context contents.

No Proto, Local API, Authority, database schema, daemon production, CLI, TUI,
Provider, Memory or Desktop change is part of this slice.

## Complete baseline and live session

`ClientAttachment::read_governed_task_baseline` authorizes
`local.task.read` before dispatch and reads `ListTaskViews` in complete pages.
The request page size is fixed at 100 and the total baseline is capped at
1,000 Tasks. All pages must carry the same snapshot position. Empty,
non-advancing or repeated cursors, position drift, duplicate Task identities,
and item 1,001 fail closed before a baseline is published. The component
evidence exercises exactly 1,000 items successfully and rejects item 1,001;
it does not rely on a smaller three-page sample as capacity evidence.

`GovernedTaskBaseline` owns an internally non-replaceable, consume-bound
snapshot position. The position remains visible through a read-only getter,
but `ClientAttachment::open_governed_task_session` consumes the baseline and a
caller cannot substitute another resume cursor. The session reuses
`TaskWatchProcessor` and therefore the existing `SnapshotStreamTracker`; it
does not implement a second stream ordering algorithm.

Applied frames update the safe Task map. Distinct Tasks at the same projection
position remain valid. Replay and Heartbeat frames do not duplicate or mutate
Task facts. ResetRequired is a one-way barrier: the current session cannot be
continued and the caller must obtain a new complete baseline. EOF, transport,
API, kernel and integrity failures remain distinguishable typed errors.

## Integrity rules

The safe mapping rejects unknown and `UNSPECIFIED` Task, Run, Step, Attempt,
recovery and projection-health enums. It requires non-empty bounded identities
and non-zero Task/Run/Step/Attempt revisions, Task and Run work revisions, and
Attempt numbers.

Projection source metadata is also bound to the mapped facts. There must be
exactly one Task source whose aggregate and revision match the Task. A mapped
Run requires exactly one Collaboration source whose aggregate and revision
match that Run; a view without a mapped Run must not contain a Collaboration
source. Other known source domains may be retained by the underlying view but
must have a non-empty identity and non-zero revision, and no source domain may
occur twice. Unknown or unspecified source domains fail closed.

For a projected Collaboration snapshot it verifies:

- the current Run belongs to the Task and has the Task work revision;
- `Run.step_ids` equals the actual ordered Step collection;
- every Step belongs to the Run;
- each Step's `attempt_ids` equals its actual ordered Attempt collection;
- `current_attempt_id`, when present, names an Attempt in that Step; and
- every Attempt is unique and binds to the same Run and Step.

A Task that names a current Run may omit Collaboration facts only for the
exact production dependency state `stale=true` plus
DependencyProjectionPending. Non-stale views and stale views carrying another
or absent reason fail closed. The allowed dependency state is not interpreted
as no Run, successful execution or Task completion.

## Automated evidence

The final local verification completed with:

```text
cargo test -p egopulse-client-operations governed_task_ --lib -- --test-threads=1
  5 passed; 0 failed

cargo test -p egopulse-client-operations --lib -- --test-threads=1
  45 passed; 0 failed

cargo clippy -p egopulse-client-operations --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The focused tests cover normal execution plus OutcomeUnknown, Reconciling,
Held and Interrupted facts; closed hold-reason classification and sensitive
hold canaries; absent/valid/unknown resume status; closed projection reasons
and unknown-reason canaries; zero and positive last Harness sequence;
checkpoint-reference presence semantics; two ordered Steps with historical
and current Attempts; zero-work-revision, unknown/unspecified enum,
source-metadata and Task/Run/Step/Attempt lineage failures; fixed-position
multipage reads;
exactly 1,000 items, item 1,001, blank/control/empty-page cursors and premature
pagination completion; permission-before-dispatch; and Applied, Replay,
Heartbeat and ResetRequired session behavior. Windows linking emitted the
known non-blocking OpenSSL LNK4099 missing-PDB warning.

## Evidence boundary

U-05a proves only the shared, read-only contract and its component behavior.
It does not claim CLI or TUI presentation, a real daemon/Windows IPC path,
restart or retention-window recovery, crash-window coverage, or coordinated
Task and Approval cursor recovery. Those R-9B integration facts remain for a
later slice.

An active resume, retry or recovery command is outside U-05. Any future U-05R
mutation capability requires a separately frozen contract and Authority
design; it must not be inferred from this read model.
