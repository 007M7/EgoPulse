# R-9B.2c CLI/TUI governed-state surface contract

- Status: FROZEN FOR IMPLEMENTATION
- Date: 2026-09-04
- Parent contract: `phase-2-77-r9b2-governed-state-driver-contract-20260904.md`
- Prerequisite evidence: `phase-2-78-r9b2b-governed-state-session-evidence-20260904.md`
- Scope: CLI and interactive TUI presentation of the shared read-only session

## Decision

R-9B.2c adds one bounded CLI watch command and one real interactive TUI page.
Both production paths must create and consume the existing
`GovernedStateSession`; neither surface may reproduce baseline acquisition,
reset/rebaseline, generation, recovery-budget, backoff, error-classification or
cross-domain scheduling logic.

The CLI path is:

```text
egopulse state watch --updates <1..1000> [--json]
```

The interactive TUI adds a Governed State page entered from the Dashboard. A
headless TUI command alone is insufficient because it would not prove the real
interactive controller lifecycle.

Existing `task watch` and Approval Queue commands/pages remain compatible.
They are not rewritten or described as atomic combined views in this slice.

## Shared semantic record

Both surfaces present the same safe semantic record:

```text
kind             = initial | update
update_index     = client-local display counter, starting at 0
changed_domain   = null | task | approval
task             = phase, closed reason, generation, recovery limit/remaining,
                   optional Task-only position, sorted safe Task facts
approval         = phase, closed reason, generation, recovery limit/remaining,
                   optional Approval-only position, sorted safe Approval facts
```

`update_index` is presentation metadata. It is not a server sequence, cursor,
checkpoint, durable offset, total order or proof that the two domain states
were observed atomically. The two positions remain separately labeled and
must never be compared or merged.

The CLI JSON form uses one bounded newline-delimited JSON record per rendered
state. Text output may be multiline. The TUI may use tables and status colors,
but the phase, reason, generation, recovery counts, positions and safe facts
must carry the same meanings.

## CLI lifecycle

1. Validate `updates` before attachment; zero or more than 1000 is rejected
   without opening a session.
2. Attach once, call `start_governed_state_session` once and render the initial
   composite with index 0 and no changed domain.
3. Consume at most `updates` successful `next_update` values. Each value renders
   the complete current composite and identifies only the changed domain.
4. A single-domain `Fatal` remains a rendered domain state; it does not stop
   consumption of the other domain.
5. Early `None` means the shared session is drained. It does not imply Task
   completion, global synchronization or success of either domain.
6. Reaching the requested bound, early `None`, Ctrl-C or a presentation failure
   closes the session exactly once through `shutdown`; `Drop` remains an
   exceptional fallback.

The CLI command owns no caller-supplied resume position. Existing domain watch
resume arguments do not cross into this command.

## Interactive TUI lifecycle

The TUI adds a `GovernedStateController` and page model. Entering the page:

1. calls the production client's shared session start once;
2. immediately shows the initial two-domain `Connecting` state;
3. runs one cancellable presentation consumer that selects between a local UI
   stop signal and `session.next_update`;
4. publishes only safe composite replacements to the page model;
5. calls `session.shutdown` before the consumer exits normally or after the UI
   requests close.

`Esc` returns to the Dashboard after stopping the controller. `q` stops the
controller before quitting the process. A domain `Fatal` updates only that
panel. A drained session is shown as stopped and does not synthesize a Task or
Approval outcome.

If the controller task cleanup is forced, dropping its still-owned session
invokes the R-9B.2b Drop guarantee. The controller cannot expose the worker
handles or cancellation sender owned by the shared session.

## Error boundary

- Session-start failure is a surface startup error and produces no false state.
- Domain failures already represented by the composite are rendered, not
  converted into process-wide errors.
- Rendering must use closed reason codes and safe facts only. Transport text,
  raw Local API errors, frames, generated clients and sensitive Harness content
  are forbidden.
- No surface event may create, cancel, retry, resume, recover, approve or mutate
  an Authority fact.

## Implementation sequence

1. Freeze pure surface record mapping and validation.
2. Implement and test the bounded CLI production command.
3. Implement and test the real TUI controller/page lifecycle.
4. Run cross-surface semantic fixtures and static boundary checks.
5. Hand off to real Windows daemon/IPC C5; do not claim C5 from component tests.

## Component acceptance gates

R-9B.2c closes only when tests prove:

1. both surfaces render initial Task and Approval `Connecting` states;
2. Task-only and Approval-only updates preserve the complete other domain;
3. parsed CLI JSON and the TUI page model agree on all shared semantic fields;
4. single-domain `Fatal` does not terminate or rewrite the other domain;
5. CLI validation, update bound and early `None` are deterministic;
6. CLI completion/cancellation and TUI Esc/q call shutdown exactly once;
7. the production CLI and TUI seams call the shared session start/next/shutdown
   path rather than a copied fake loop;
8. static inspection finds no surface-owned recovery budget, generation
   advancement, reset/rebaseline, reconnect backoff or cross-domain order;
9. no Proto, RPC, Authority, database or write-capability change is present.

## C5 handoff

Component completion does not prove a daemon process, Windows IPC, restart,
retention reset, real permission rejection, process cleanup or Authority-store
zero-write evidence. Those remain the subsequent R-9B C5 gate.
