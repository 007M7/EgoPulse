# R-9B.1 governed-state reducer evidence

Status: ACCEPTED

Date: 2026-09-04

Contract SSOT: `phase-2-75-r9b-governed-state-dual-stream-contract-20260904.md`

## Closed scope

R-9B.1 adds the runtime-agnostic Rust reducer for composing the existing
governed Task and actionable Approval read domains. It does not integrate a
client attachment, acquire a baseline, hold a stream, schedule a worker, or
add a CLI/TUI user flow. Those responsibilities remain in R-9B.2.

Implemented files:

- `crates/client-operations/src/governed_state.rs`
- `crates/client-operations/src/lib.rs`

No Cargo dependency, Proto, RPC, database, Authority writer, command gateway,
provider, Memory/RAG, Desktop, or release surface changed.

## Accepted semantic surface

The public read-only surface exposes:

- separate Task and Approval domain states;
- independent lifecycle phases: `Connecting`, `Live`, `Stale`,
  `ResetRequired`, and `Fatal`;
- safe reason codes;
- domain-specific diagnostic positions with getters only;
- independent generation, recovery limit, and remaining-budget values;
- safe Task facts and the minimal Approval correlation pair
  `approval_request_id` / `task_id`.

The public surface exposes no cursor constructor, cursor setter, caller-owned
resume position, cross-domain comparison, combined checkpoint, raw Proto
frame, generated client, `SnapshotStreamTracker`, command client, or Authority
mutation capability.

## Reducer invariants proved

1. Task and Approval facts, position, generation, phase, reason, and recovery
   budget are independent.
2. Every Task input preserves the complete Approval domain; every Approval
   input, including removal, preserves the complete Task domain.
3. Initial failure is not all-or-nothing: either domain may become `Fatal`
   while the other independently reaches and remains `Live`.
4. Recoverable failure consumes only the matching domain's finite budget and
   advances only its generation fence. Transport, EOF, and an API rejection
   already classified as retryable use distinct internal causes; callers
   cannot pass an arbitrary public reason into the recoverable path.
5. Strict forward progress may recover `Stale` to `Live` and refill only the
   matching domain's budget to its own immutable limit.
6. Replay, Heartbeat, same-position, and stale-generation inputs do not publish
   facts, refill budget, or alter the other domain.
7. `ResetRequired` immediately advances the matching generation and blocks old
   session input. It accepts only a matching complete rebaseline or an explicit
   rebaseline outcome.
8. A recoverable rebaseline failure preserves last-good facts, consumes only
   the matching budget, and advances the matching generation. Exhaustion is
   terminal.
9. Complete rebaseline atomically replaces only the matching domain and does
   not count as forward progress or refill recovery budget.
10. Failed or partial rebaseline preserves last-good facts, position,
    generation, and budget while moving only the matching domain to `Fatal`.
11. `Fatal` is terminal inside one reducer lifetime.
12. Task and Approval positions are never compared; opposite event
    interleavings converge to the same pair of per-domain states.

## Fault and component evidence

The focused module contains 11 passing tests, including:

- symmetric initial single-domain fatal behavior;
- exhaustive Task-to-Approval and Approval-to-Task isolation matrices;
- symmetric fatal-reason, reset, recovery, and budget-exhaustion cases;
- Replay, Heartbeat, same-position, and stale-generation no-publication cases;
- complete, failed, recoverable-failure, and partial rebaseline cases;
- cross-domain interleaving without global ordering.

The shared fixture enters `Live` only through `Connecting` followed by the
actual `CompleteRebaseline` reducer input. It no longer writes phase, position,
or facts directly.

Independent verification completed with:

```text
cargo test -p egopulse-client-operations governed_state -- --test-threads=1
  11 passed; 0 failed

cargo test -p egopulse-client-operations -- --test-threads=1
  56 passed; 0 failed

cargo clippy -p egopulse-client-operations --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The Windows linker continues to emit the pre-existing missing
`ossl_static.pdb` LNK4099 debug-symbol warning. It does not change test or
Clippy results and is not an R-9B.1 product defect.

## Independent reviews

Final independent test review: GO, P0 = 0, P1 = 0, P2 = 0.

Final architecture review: GO, P0 = 0, P1 = 0. Its sole P2 was a comment that
named the future consumer as an R9B.1 driver; the comment was corrected to
R9B.2 before closure.

## Collaboration accounting

The isolated ZCode worktree contributed the reducer-driven test fixture,
symmetric initial failure proof, and exhaustive per-input domain-isolation
tests. Its diff was restricted to the `#[cfg(test)]` module and was integrated
as a separate auditable commit. The main builder implemented the reducer and
the remaining fault matrices. Architecture and test windows remained
read-only.

## Explicitly not claimed

R-9B.1 does not claim:

- same-attachment binding;
- baseline/session I/O;
- bounded workers, channel capacity, cancellation, or scheduling fairness;
- CLI/TUI integration;
- real daemon/IPC, restart, reset-retention, or permission C5 evidence;
- R-9C governed content disclosure;
- any Authority write or Task completion inference.

These remain the R-9B.2 and subsequent C5 work. R-9C remains blocked on the
Founder disclosure decision frozen in the contract SSOT.
