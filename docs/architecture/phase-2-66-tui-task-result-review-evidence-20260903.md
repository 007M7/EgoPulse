# U-03b TUI governed task-result review evidence

- Date: 2026-09-03
- Scope: TUI Task selection and read-only result/governance review
- Status: locally verified
- Parent flow: U-03 Result Review

## Outcome

U-03b exposes the U-03a shared task-result review through the production TUI.
It does not create a second business kernel. The TUI captures only the Task ID
currently selected in Task Watch and delegates the read to
`ClientAttachment::read_task_result_review` through the same attached client
used by the other interactive surfaces.

The TUI cannot accept caller-authored ArtifactSet, Verification or Founder
Verdict identities. It contains no result write, Task completion, Verdict
issue/consume, artifact-byte read, Proto, Local API, Authority, database,
Provider, Memory or Desktop change.

## Interaction and lifecycle

Task Watch now maintains selection by stable Task identity rather than row
position. `Up` and `Down` change the selection and `Enter` opens review for the
selected Task. Sorting, projection updates and full refetch preserve the same
Task identity. If the Task leaves the projection, selection moves
deterministically to an adjacent available row and the user is told that the
previous selection disappeared.

Before Result Review starts, the Task Watch worker is stopped. Approval Queue,
Task Watch and Result Review controllers are mutually exclusive. Result Review
provides five sections:

1. Summary;
2. Artifacts / Claims / Evidence;
3. Verification;
4. Founder Verdict / State;
5. Projection / Redactions.

`Tab` and `BackTab` change section, arrow and page keys scroll, `r` performs one
explicit refresh, `Esc` stops review and reopens Task Watch with the reviewed
Task reselected when it still exists, and `q` performs bounded cleanup before
exit. The page continuously states that governance evidence does not complete
the Task.

## Safe view and failure semantics

The one-shot worker converts the already validated `TaskResultReview` into a
TUI-owned safe page model before crossing its bounded channel. App state does
not retain the raw Proto result. The safe view presents content addresses,
contract references, lineage, Artifact/Claim/Evidence relationships,
Verification criteria/discrepancies/unverified items, Founder risk/rework
facts, Verdict state and projection/redaction metadata.

It excludes principal identities, authority and confirmation proofs,
workspace paths, raw-source and native-execution references, raw Provider or
Harness content and artifact bytes. Missing components render as
`Not projected`; they are not inferred to be passed, rejected or complete.
Task status is shown only from the Task Authority projection.

The worker channel capacity is one. Every terminal event carries a generation
fence; late success and failure from an older generation are discarded.
Refresh cancels the previous generation. Stop and Drop signal cancellation,
then use a bounded join with abort fallback, including when delivery is blocked
by a full channel.

A read failure stops the current runtime but retains the controller and Task
identity. It never retries automatically. The user may press `r` to start
exactly one new generation. A last-good page is retained only as explicitly
stale; without one, the UI remains a safe unavailable placeholder. `Esc`
continues to return to Task Watch after either outcome.

## Automated evidence

```text
cargo test -p egopulse-tui -- --test-threads=1
  library: 15 passed
  binary:  25 passed
  total:   40 passed; 0 failed

cargo test -p egopulse-client-operations
  35 passed; 0 failed

cargo clippy -p egopulse-tui -p egopulse-client-operations --all-targets -- -D warnings
  passed

cargo check -p egopulse-tui --all-targets
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The tests cover stable selection and deterministic fallback, zero read with no
selection, capture of the current selected identity, exactly one read,
type-safe failure, stale-generation rejection, refresh cancellation, blocked
channel cancellation, bounded stop/abort/Drop, sensitive sentinel exclusion,
`Not projected`, Active plus Verdict without false completion, production App
controller mutual exclusion and cleanup. A dedicated App-seam regression proves
that an initial integrity failure performs no automatic retry, `r` increments
the read count from one to exactly two, and `Esc` restores the original Task
selection.

Independent implementation/test review returned `GO` with P0=0, P1=0 and
P2=0. Static interaction review also returned `GO`. Run/Step/Attempt statuses
remain an execution-state enhancement for Task Watch rather than a duplicate
result-page model; Result Review already exposes their exact governance binding
through Artifact and Verification lineage. The Windows linker emitted only the
known non-blocking missing `ossl_static.pdb` LNK4099 debug-symbol warning.

## Evidence boundary

U-03b proves the production TUI controller and App seams, safe rendering,
selection correctness and bounded local lifecycle. It does not prove a real
daemon process, real Windows IPC, Authority-store equality before and after
reads, same-root restart replay, an interactive terminal subprocess, Provider
admission, artifact-byte viewing or Task completion. The daemon, persistence
and restart claims belong to U-03c.
