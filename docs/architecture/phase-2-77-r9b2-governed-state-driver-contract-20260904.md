# R-9B.2 governed-state driver contract

Status: FROZEN FOR IMPLEMENTATION

Date: 2026-09-04

Parent SSOT: `phase-2-75-r9b-governed-state-dual-stream-contract-20260904.md`

Prerequisite evidence:
`phase-2-76-r9b1-governed-state-reducer-evidence-20260904.md`

## Decision

R-9B.2 binds the R-9B.1 reducer to the existing governed Task and actionable
Approval baseline/session APIs. One public session is backed by exactly two
independent domain workers. Both workers receive clones of the same
`Arc<ClientAttachment>` and must not attach again.

The implementation remains in `egopulse-client-operations`:

- `governed_state.rs` remains the runtime-agnostic reducer;
- `governed_state_driver.rs` owns attachment I/O, workers, channels,
  cancellation and error classification;
- `lib.rs` exports only the safe session/update surface;
- `Cargo.toml` adds the existing workspace-pinned Tokio dependency.

No Proto, RPC, Authority, database, schema, provider, Memory/RAG, R-9C,
Desktop, CLI presentation or TUI presentation contract changes in this slice.

## Why this design

The existing `client-operations` crate already owns the authenticated
attachment and the only approved Task/Approval list/watch operations. Keeping
the driver here lets CLI and TUI consume one implementation without copying
permission, replay, reset or recovery logic.

Two independent bounded queues are selected instead of one shared queue. A
single hot domain cannot occupy the other domain's capacity, and a blocked or
pending domain cannot prevent the session from polling the other. The session
alternates preferred domains whenever both are ready; event interleaving has
no governance meaning.

The cost is that `client-operations` gains a Tokio worker lifecycle and becomes
the owner of shutdown correctness. A new runtime crate was rejected for this
slice because it would add another public package boundary without separating
any additional authority or deployment responsibility. That decision may be
revisited only if a future non-Tokio client must share the runtime itself; the
pure R-9B.1 reducer remains runtime-independent.

## Public surface

The semantic public API is:

```text
ClientAttachment::start_governed_state_session(self: &Arc<Self>)
  -> Result<GovernedStateSession, GovernedStateSessionStartError>

GovernedStateSession
  state() -> &GovernedStateComposite
  next_update() -> Future<Option<GovernedStateUpdate>>
  shutdown(self) -> Future<GovernedStateShutdown>

GovernedStateUpdate
  domain() -> GovernedStateDomain
```

`state()` is a local display snapshot containing two independent domain
states. It is not an atomic server snapshot and cannot expose or imply a
combined cursor, epoch, sequence, checkpoint or total order.

The session never exposes a reducer input, raw frame, generated client,
`SnapshotStreamTracker`, command client, resume cursor constructor, worker
handle or cancellation sender.

## Coordination and backpressure

1. The Task worker and Approval worker each own a distinct bounded channel of
   capacity one.
2. A worker sends at most one reducer request and waits for its acknowledgement
   before polling its source again.
3. Sending uses cancellable channel reservation. Full capacity cannot cause
   additional stream polling or an unbounded buffer.
4. `GovernedStateSession::next_update` checks the preferred queue first, then
   the other queue, and flips preference after each accepted event.
5. If neither queue is ready, it waits on both without assigning semantic
   ordering to the winner.
6. A request acknowledgement returns only the matching domain's phase,
   generation and remaining budget required for the worker's next action.
   Workers cannot directly mutate state or invent recovery decisions.

## Initialization and same-attachment binding

The session returns immediately with both domains in `Connecting`.

Each worker independently:

1. calls its existing baseline operation on the shared attachment;
2. passes that complete baseline into its existing session-open operation;
3. reads the safe facts and position from the successfully opened session;
4. sends `CompleteRebaseline` using its current generation;
5. enters live polling only after the reducer accepts the complete state.

A baseline is never published before the matching session has consumed it.
Failure in one worker cannot cancel initialization of the other. Permission is
checked independently by the existing List and Watch paths; neither domain may
borrow the other's permission.

## Update and recovery mapping

Live stream outcomes map as follows:

- Applied -> matching `Applied` or Approval `Remove` input;
- Replay -> `Replay`;
- Heartbeat -> `Heartbeat`;
- reset barrier -> `Reset`, retire the old session, refetch;
- transport or EOF -> `RecoverableFailure`, retire the old session, retry;
- protocol/integrity or non-retryable rejection -> `Fatal`.

Initialization/refetch outcomes map as follows:

- complete baseline consumed by a matching session -> `CompleteRebaseline`;
- transport, EOF, or API error explicitly marked retryable ->
  `RebaselineRecoverableFailure` after the first attempt;
- partial/integrity result -> `RebaselinePartial`;
- permission, session/contract, baseline limit, protocol, or non-retryable API
  error -> `Fatal` initially or `RebaselineFailed` during recovery.

An API error marked retryable uses the restricted internal
`RetryableApiRejected` cause. It is not mislabeled as transport and cannot
bypass the reducer budget.

Every I/O attempt captures the current domain generation. All returned events
carry that captured token. Failure/reset advances the reducer generation, so a
late result from an old session is ignored. Workers read the accepted
generation only from the acknowledgement.

## Cancellation and shutdown

The public session exclusively owns the cancellation sender and both join
handles.

Cancellation must cover all worker wait points:

- baseline and session-open I/O;
- live stream receive;
- channel reserve/send and acknowledgement;
- reconnect delay.

Production defaults are local-only and bounded:

- independent queue capacity: 1 per domain;
- recovery limit: 3 per domain;
- reconnect delay: 100 ms;
- graceful shutdown bound: 2 seconds.

Tests may inject deterministic timing and controlled pending futures through a
private seam. Public callers cannot request an unbounded channel, recovery
budget, retry delay or shutdown wait.

`shutdown` sends cancellation, waits within the fixed bound, and aborts any
worker that exceeds it. `Drop` sends cancellation and aborts remaining handles
so a session cannot leave an orphan worker holding the attachment.

## Implementation slices

### R-9B.2a: source and classification

- add the production Task/Approval source wrappers around the existing
  baseline/session APIs;
- convert only complete consumed sessions into safe reducer inputs;
- centralize typed error/stage classification;
- prove same attachment and independent permission dispatch;
- no background worker yet.

### R-9B.2b: session and workers

- add two capacity-one channels and acknowledgement flow;
- add fair `next_update` coordination;
- add generation-aware retry/reset loops;
- add cancellation over receive, reserve/send, ack and backoff;
- add bounded shutdown and Drop cleanup.

### R-9B.2c: surface reuse

- make CLI and TUI consume the same public session;
- no duplicated recovery state machine in either surface;
- presentation changes stay within the previously frozen three-surface model.

Real process/IPC and persistent zero-write evidence remains the subsequent R-9B
C5, not a component-test claim.

## Component acceptance gates

R-9B.2 is not closed until deterministic tests prove:

1. initial Task failure with Approval Live and the symmetric case;
2. the exact same attachment object feeds both domains;
3. independent List/Watch permission checks and zero dispatch for the denied
   domain while the other advances;
4. a hot or permanently pending worker cannot starve the other;
5. full channel capacity prevents further source polling;
6. cancellation stops receive, send-reserve/ack and reconnect-delay waits;
7. EOF/transport and budget exhaustion affect only one domain;
8. Reset retires the old session and refetches only the affected domain;
9. late old-generation events cannot publish;
10. complete/failed/partial/retryable rebaseline preserves R-9B.1 semantics;
11. only existing Task/Approval List/Watch operations are callable;
12. no command or Authority write surface exists in the driver.

Tests use barriers, controlled pending futures and exact counters. Sleep-based
probabilistic assertions are not accepted.

## Real C5 handoff

Component gates do not claim:

- Windows daemon child process or real IPC;
- same-root/instance restart with a different PID;
- real single-domain disconnect or daemon retention reset;
- real session permission rejection;
- real CLI/TUI shared-driver execution;
- READ_ONLY/query_only full Authority-store before/after evidence;
- bounded process and worker cleanup under the real daemon.

Those remain mandatory R-9B C5 evidence after R-9B.2a-c are complete.
