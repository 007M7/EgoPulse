# R-9B.2b governed-state session evidence

- Status: CLOSED AT COMPONENT LEVEL
- Date: 2026-09-04
- Parent contract: `phase-2-77-r9b2-governed-state-driver-contract-20260904.md`
- Scope: shared Rust session, workers, supervision and cleanup only

## Result

`egopulse-client-operations` now owns one public `GovernedStateSession` backed
by exactly two independent capacity-one workers. The Task and Approval workers
use clones of the same `Arc<ClientAttachment>`, retain separate generations and
recovery budgets, and can neither expose a write operation nor infer a combined
cursor or cross-domain order.

The public surface is limited to:

- `ClientAttachment::start_governed_state_session`;
- `GovernedStateSession::state`;
- `GovernedStateSession::next_update`;
- `GovernedStateSession::shutdown`;
- `GovernedStateUpdate::domain`.

No Proto, RPC, Authority, database, provider, Memory/RAG, CLI, TUI or Desktop
contract changed in this slice.

## Worker and supervisor guarantees

- Each worker reserves its own bounded queue, submits one reducer input and
  waits for the matching domain acknowledgement before reading again.
- Baseline/session open, live receive, reserve, acknowledgement and recovery
  backoff are all cancellation-aware.
- The reducer remains the sole owner of generation, recovery and fatal-state
  decisions.
- A normal `DomainFatal` exit is retired without a duplicate synthetic update.
- Request-channel loss, acknowledgement loss, an unexpected active
  cancellation or `JoinError` maps once to the affected domain's existing
  `ProjectionIntegrityFailure`; the other domain remains usable.
- `next_update` returns `None` only after both workers retire and both queues
  are drained and closed.
- Once both core queues are exhausted, the session waits only for remaining
  joins. This prevents an immediately-ready core future from starving worker
  completion on a current-thread Tokio runtime.
- `shutdown` sends cancellation, waits under one fixed two-second deadline and
  aborts remaining workers. `Drop` synchronously sends cancellation and aborts
  any handles still owned by the session.

## Deterministic evidence

The component suite proves:

- initial state and single-domain reducer isolation;
- independent capacity-one queues, fairness and pending-domain progress;
- same-attachment source construction and independent permission dispatch;
- bounded reset/recovery, generation mismatch retirement and session drop;
- cancellation at open, live receive, reserve, acknowledgement and backoff;
- request-channel and acknowledgement typed exits;
- real spawned worker panic isolation;
- normal fatal retirement without a second domain update;
- graceful shutdown, forced abort and Drop cleanup with started-worker
  witnesses;
- exhausted-core completion on a current-thread runtime without sleep.

Local verification command:

```powershell
cargo test -p egopulse-client-operations -- --test-threads=1
cargo clippy -p egopulse-client-operations --all-targets -- -D warnings
cargo fmt --all -- --check
```

Result: `102 passed, 0 failed`; Clippy and formatting passed. The Windows linker
emitted the existing missing `ossl_static.pdb` debug-symbol warning; it did not
change the test result.

## Traceability

- `25d07c2` exposes the bounded public session lifecycle.
- `6e7a14c` proves shutdown, forced abort, Drop and exhausted-core completion.
- `84c798a` proves typed worker exits fail only their own domain.
- `e90dd0e` proves real panic isolation and normal `DomainFatal` retirement.

## Remaining handoff

This closes R-9B.2b only. R-9B.2c must make CLI and TUI consume this same
session without copying its recovery state machine. The subsequent R-9B C5
must still prove real Windows daemon/IPC behavior, restart and retention reset,
independent permission rejection, bounded process cleanup and read-only
Authority-store evidence.
