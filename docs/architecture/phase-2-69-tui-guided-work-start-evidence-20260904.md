# U-04b TUI guided Work Start evidence

- Date: 2026-09-04
- Scope: TUI guided Work Start component and lifecycle integration
- Status: locally verified
- Parent flow: U-04 Guided Work Start

## Outcome

U-04b composes the shared guided Work Start operation from U-04a into the
production TUI. The Dashboard opens the flow with `n`; the user edits only
high-level intent, work type, target scope and Context references. Preparation,
preview confirmation, exact replay and Task identity handling stay behind
`egopulse-client-operations` and the production `WorkStartController`.

The controller and the TUI use the same attached `ClientAttachment`. The TUI
does not construct Context snapshots, confirmation bindings, idempotency keys,
Task commands or other Authority-owned fields. The existing scripted Work
Prepare and Work Confirm commands remain compatible and unchanged.

No Proto, Local API, Authority, database schema, agentosd production, Provider,
Memory or Desktop contract changes are part of this slice.

## Lifecycle and recovery behavior

- `PreparedWork` and the preparation and confirmation recovery values remain
  linear opaque capsules. The page cannot clone, forge or replace their sealed
  request and binding facts.
- The mutation event channel has capacity one and uses a generation fence.
  Superseded terminal events retire their completed runtime without opening a
  preview or Task Watch and without overwriting the current page state.
- An in-flight Prepare or Confirm worker is never aborted. `Esc`, quit and page
  cleanup wait for settlement within a bounded interval; an unresolved worker
  remains owned by the controller and prevents the application from exiting or
  discarding the operation.
- `Esc` during Editing sends no RPC. `Esc` from PreviewReady explicitly drops
  the prepared confirmation and states only that Task confirmation was not
  sent. A blocked or not-ready preview cannot dispatch Confirm, and repeated
  `Enter` cannot dispatch a second confirmation.
- PreparationOutcomeUnknown and ConfirmationOutcomeUnknown retain their exact
  recovery capsule. `Enter` performs only the corresponding exact replay.
  ConfirmationOutcomeUnknown may open observation-only Task Watch with `w`;
  this preserves the recovery capsule and does not authorize replacement
  preparation, cancellation or completion.
- A confirmed result uses only the returned authoritative `task_id`. Task Watch
  retains that exact pending selection while projection catches up. While the
  target is absent, the page has no actionable selected Task, so another Task
  cannot be opened accidentally. The exact Task is selected only after it
  appears in the governed projection.
- Task Watch, Approval Queue, Result Review and Work Start lifecycles remain
  mutually controlled. Normal navigation and abnormal session cleanup cannot
  discard an active mutation or an outcome-unknown recovery capsule.

## Safe rendering

The Work Start renderer consumes only the TUI-owned safe page projection and
the shared typed `GuidedWorkNonGoal` and `GovernedWorkNotice` values. It renders
the validated intent summary, governed work type and scope, source counts,
readiness, fixed non-goals and fixed blocker codes. It has no field for raw
reason, evidence, proof, source content, source detail, Context digest,
snapshot binding, principal or idempotency data.

A production-renderer `TestBackend` test injects representative raw reason,
evidence, proof, source and digest canaries through an underlying error and
proves that only the fixed safe integrity message and typed notice reach the
terminal buffer.

## Changed files

- `apps/tui/src/work_start.rs`: production controller, linear worker lifecycle,
  safe page projection and renderer, plus controller and rendering tests.
- `apps/tui/src/lib.rs`: exports the Work Start module.
- `apps/tui/src/main.rs`: Dashboard/editor/preview/recovery wiring, protected
  exit and page transitions, exact confirmed-Task selection, and action tests.
- `apps/tui/src/task_watch.rs`: adds a local selection-clear operation used
  while an exact confirmed Task projection is pending; it does not alter Task
  facts.

## Automated evidence

The final local verification completed with:

```text
cargo test -p egopulse-tui -- --test-threads=1
  library: 21 passed; 0 failed
  binary: 28 passed; 0 failed
  total: 49 passed; 0 failed

cargo clippy -p egopulse-tui --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The tests cover linear prepare and confirm ownership, blocked confirmation,
preview cancellation, in-flight settlement without abort, exact recovery
replay counts, stale generation retirement, confirmed Task identity, projection
lag with no wrong selection, protected quit and navigation, observation-only
reconciliation, safe typed rendering, and combined key-to-production-action
evidence that blocked, repeated, pending and outcome-unknown interactions do not
duplicate mutations.

Windows linking emitted the known non-blocking LNK4099 warnings for missing
OpenSSL PDB debug-symbol files. The tests and Clippy completed successfully;
the warnings do not change the verified behavior in this slice.

## Evidence boundary

U-04b proves the TUI component and application lifecycle integration over the
shared guided Work Start operation. It does not complete U-04.

U-04c is now locally verified by
`phase-2-70-guided-work-start-real-daemon-evidence-20260904.md`. It exercises
this production controller against a real daemon and Windows IPC, binds the
confirmed Task to the durable stores, and drives the normal TUI through a real
ConPTY session. The evidence remains local debug-binary evidence: it does not
prove packaged installation or recovery-capsule persistence across a client
process restart.
