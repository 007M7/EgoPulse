# U-05c TUI execution and recovery view evidence

- Date: 2026-09-04
- Scope: TUI presentation of the shared U-05a governed Task baseline/session
- Status: locally verified
- Parent flow: U-05 user-readable execution and recovery review

## Outcome

U-05c migrates the interactive TUI Task Watch page to the shared
`egopulse-client-operations` governed Task operation. The production
controller uses the existing attached `ClientAttachment` to read one complete
`GovernedTaskBaseline`, publishes that safe baseline atomically as Connecting,
and consumes the same opaque baseline through `open_governed_task_session`.
Only a successful session open advances the page to Live. The page no
longer owns raw `TaskView`, projection frames, `TaskWatchRequest`, a generated
watch client, or `SnapshotStreamTracker`.

The view is read-only. It exposes safe Task, Run, Step and Attempt identities,
revisions, typed states, classified hold/recovery facts, Run work revision,
current Attempt identity, last Harness sequence and whether a checkpoint
reference was recorded. Projection epoch/sequence, health, stale state and a
classified reason remain visible. It excludes workspace, Harness/profile,
dispatch/session/lease/fence, checkpoint identity, Context, Artifact,
Provider/model and content data. A terminal child Run, Step or Attempt never
synthesizes Task completion; the page explicitly says that governance evidence
does not complete the Task.

## Stream and lifecycle behavior

Applied updates replace or insert the safe Task tree by Task identity. Replay
updates, including replayed safe snapshots, and Heartbeats do not change Task
facts. ResetRequired retires the old session and requires a complete atomic
rebaseline before another consume-bound session opens. Automatic reset rebases
are limited to three; a fourth consecutive reset stops fail-closed. A baseline,
Replay, or same-position Applied/Heartbeat does not clear that budget. Only an
Applied or Heartbeat position strictly later than the new baseline clears it.

EOF and transport interruption use the existing bounded 250/500/1000/2000/2000
millisecond schedule and a full rebaseline. Each opened session retains its
baseline floor. Replay and same-position Applied/Heartbeat frames do not reset
the reconnect budget; only an Applied or Heartbeat position in the same epoch
and strictly later than that floor resets it. Permission, session, API,
integrity/protocol and baseline-limit failures stop without retry. Page errors
are closed safe messages rather than formatted internal errors. The controller
uses one bounded 32-event channel, generation fencing, cancellation-aware
sends, a bounded stop and worker abort fallback. User `r` starts a new
generation and resets the automatic recovery budget.

Selection is stable by authoritative Task identity across sorting, updates and
rebaselines. If a selected Task disappears, selection moves deterministically;
detail scrolling resets. Up/Down changes selection and PageUp/PageDown moves a
deterministically clamped detail viewport. Enter opens the existing Result
Review only for a real selected Task. When guided Work Start has confirmed an
exact Task whose projection has not arrived, the page has no actionable
selection: unrelated Applied updates and reset/rebaseline cannot select another
Task, and only arrival of the exact Task consumes the pending selection.

## Evidence

Component and application tests cover:

- complete-baseline publication before opening its consume-bound session;
- explicit Connecting-to-Live ordering and an open failure that never claims
  the published baseline is Live;
- Applied, Replay-with-snapshot and Heartbeat reducer behavior, including an
  Active Task whose Run is Returned remaining Active;
- three-reset budgeting, fourth-reset fail-closed behavior, same-position
  negative cases, and separate strictly-later Applied/Heartbeat reset cases;
- EOF/transport full rebaseline, exact five-delay exhaustion without a hot
  loop, Replay/EOF/transport and same-position non-progress counterexamples,
  separate strictly-new Applied/Heartbeat reconnect resets, fixed safe
  permission/integrity/limit errors, and atomic preservation of the last
  complete model when a rebaseline fails;
- generation fencing, bounded-channel cancellation and bounded stop;
- stable selection plus detail scroll clamp/reset after selection changes,
  shortened facts and rebaseline;
- exact confirmed-Task projection lag across missing target, unrelated Applied
  and Reset/rebaseline; and
- application failure handling that retires Task Watch without mutating the
  independent Dashboard snapshot; and
- wide and narrow `ratatui::TestBackend` rendering of the nested safe fact tree
  without sensitive-field canaries or false completion.

The public, doc-hidden `from_safe_projection_adapter` constructors accept only
the already-safe U-05 DTOs for custom `TaskWatchClient` component evidence.
They do not constitute daemon or Authority evidence.

Local verification completed with:

```text
cargo test -p egopulse-tui -- --test-threads=1
  library: 33 passed; binary: 29 passed

cargo clippy -p egopulse-tui --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The Windows linker may emit the existing missing `ossl_static.pdb` debug-symbol
warning; it does not change the successful test result.

## Explicit boundary

This is the U-05c TUI component and application seam. It does not claim a real
daemon/Windows IPC or packaged-terminal test, durable database zero-write
evidence, coordinated Task/Approval cursors, restart/retention coverage, or an
active retry/resume/recover operation. Those remain U-05d, R-9B or a separately
frozen U-05R scope. No Proto, Local API, Authority, database schema, daemon,
Provider, Memory or Desktop behavior changed.
