# U-05b CLI execution and recovery view evidence

- Date: 2026-09-04
- Scope: CLI presentation of the shared U-05a governed Task baseline/session
- Status: locally verified
- Parent flow: U-05 user-readable execution and recovery review

## Outcome

U-05b migrates the existing `task watch` command to the shared
`egopulse-client-operations` governed Task operation. The command now attaches,
reads one complete `GovernedTaskBaseline`, emits that baseline atomically,
consumes it through `open_governed_task_session`, and then reads bounded live
updates. The CLI no longer owns `TaskWatchRequest`, the raw Task view stream,
raw projection frames, or `SnapshotStreamTracker`.

The existing interface remains compatible:

```text
egopulse task watch --frames <1..1000> \
  [--resume-epoch <epoch> --resume-sequence <sequence>] [--json]
```

The resume pair is a minimum projection-position floor, not a historical
replay cursor. A single resume argument fails before attachment. For the same
epoch, a baseline at or beyond the requested sequence proceeds from that
latest complete baseline; a baseline behind the floor returns
`PROJECTION_NOT_CAUGHT_UP` without opening a watch. An epoch mismatch emits a
safe reset-compatibility notice and then continues from the current complete
baseline. Historical replay and coordinated Task/Approval cursors remain an
R-9B concern.

## Output and recovery behavior

JSON output retains the common `egopulse.cli-result/v0.1` envelope and adds the
stable stream schema `egopulse.cli.task-watch/v1`. A baseline is one envelope
with the complete safe Task array. A live update contains at most one safe
Task; Heartbeat and ResetRequired always render `task: null`. Text output is a
readable projection of the same safe fact tree.

The rendered fields are limited to the U-05a DTO: Task, Run, Step and Attempt
identities; revisions; typed status, resume, recovery and closed reason facts;
Run work revision; current Attempt identity; last Harness sequence;
checkpoint-reference-recorded; and projection position, health, stale state
and closed reason. It does not render raw Task views, workspace/Harness/profile
or dispatch bindings, sessions, leases, fencing tokens, checkpoint identity,
Context, Artifact, Provider/model or content data. Run, Step or Attempt
terminal state is never used to synthesize Task completion.

`--frames` counts live frames only; neither the initial baseline nor an epoch
mismatch notice consumes the budget. A live ResetRequired frame retires its
session. If more live frames are requested, the command obtains and emits a
new complete baseline and opens a new consume-bound session. This rebase is
limited to three per invocation; exceeding the budget returns
`RESET_REQUIRED`. When ResetRequired is the final requested frame, the old
session is dropped and the command exits without an unnecessary baseline or
watch RPC. EOF and transport failures stop with a safe rerun instruction and
never auto-reattach.

## Evidence

The CLI tests exercise:

- baseline-before-watch ordering and exact live-frame accounting;
- accepted older floors, ahead floors with zero watch, and epoch mismatch;
- complete resume-pair and 1..1000 frame validation;
- safe JSON/text trees and forbidden-field canaries;
- Applied, Replay, Heartbeat and ResetRequired presentation;
- reset-driven replacement baselines, the three-rebase bound, and final-reset
  zero-extra-IPC behavior;
- EOF/transport termination without reattach or extra poll; and
- safe permission, session, API, protocol, baseline-limit and reset error
  categories.

Local verification completed with:

```text
cargo test -p egopulse-cli governed_task_watch -- --test-threads=1
  8 passed; 0 failed

cargo test -p egopulse-cli -- --test-threads=1
  28 passed; 0 failed

cargo clippy -p egopulse-cli --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

Windows linking emitted the existing non-blocking OpenSSL missing-PDB LNK4099
warning during tests.

## Evidence boundary

This slice proves the CLI adapter and its component seams. It does not claim a
new wire contract, Authority mutation, daemon runtime change, TUI integration,
historical stream replay, coordinated Task/Approval cursor recovery, daemon
restart/retention/crash-window behavior, or an active resume/retry/recover
operation. Those capabilities require their separately frozen slices.
