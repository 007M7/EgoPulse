# R-9B governed-state dual-stream composition contract

- Status: Founder-frozen R-9B boundary; R-9B.1 implementation authorized
- Date: 2026-09-04
- Decision owner: Founder
- Decision authority: conversation:2026-09-04:founder-authorized-plan-continuation
- Scope: R-9B governed-state projections only
- Runtime fact owners: Task Authority, Collaboration Control and Policy Decision Authority
- Composition owner: shared Rust client operations

## Decision

R-9B composes the existing governed Task and actionable Approval projection
streams in the shared Rust client layer. It does not create a third wire
stream, a global cursor, a cross-domain transaction or a total event order.

The Task and Approval domains retain separate complete baselines,
consume-bound sessions and opaque projection positions. Their positions must
not be compared, merged or represented as one atomic checkpoint, even when an
epoch or sequence value happens to match.

Both domains use the same authenticated `ClientAttachment`. Task operations
retain the existing `local.task.read` permission boundary. Approval operations
retain `local.approval.read`. The composite cannot infer, grant or substitute a
permission.

## Existing contract foundations

R-9B reuses, without changing their wire contracts:

- `GovernedTaskBaseline` and `GovernedTaskSession`;
- `ApprovalQueueBaseline` and `ApprovalQueueSession`;
- complete bounded pagination for both baselines;
- consume-on-open ownership of each private baseline position;
- the existing Task and Approval list/watch Local API operations;
- the accepted session, principal and permission checks in one
  `ClientAttachment`.

The old Dashboard `read_projection_snapshot` is not an R-9B baseline. It is a
sequential convenience read, is not consume-bound and cannot supply either
private stream position.

## Authority and permission boundaries

The composite is strictly read-only. It may call only the existing Task and
Approval list/watch operations. It cannot hold or invoke a command-gateway
client and cannot create, confirm, cancel, retry, resume, recover, approve or
mutate any Authority fact.

Projection updates, Approval observations, Harness observations and recovery
facts never complete a Task and never imply Founder acceptance, Verification
success or Artifact release.

A missing Task permission makes only the Task domain unavailable. A missing
Approval permission makes only the Approval domain unavailable. Neither
permission can be borrowed from the other domain. A shared attachment failure
may affect both domains, but each domain still reports its own resulting
state.

## End-state composite responsibility

The shared Rust operation owns:

- one private Task baseline/session/position and one private Approval
  baseline/session/position;
- the last complete safe facts and lifecycle state for each domain;
- independent finite recovery budgets and generation fences;
- domain-specific error classification and safe reason codes;
- atomic replacement of only the affected domain after a successful full
  rebaseline;
- a bounded, cancellable coordination seam that allows both domains to make
  progress without one indefinitely starving the other.

The semantic API exposes safe facts and domain lifecycle only. A diagnostic
position may be exposed read-only for its own domain, but there is no public
cursor constructor, cursor setter, `From` conversion, caller-supplied resume
position, combined epoch or combined sequence. Raw Proto frames, generated
clients and `SnapshotStreamTracker` remain private.

Implementation names may follow the existing crate style, but the semantic
surface is equivalent to:

```text
GovernedStateComposite
  task: GovernedStateDomainState<TaskFacts>
  approval: GovernedStateDomainState<ApprovalFacts>

GovernedStateDomain = Task | Approval
GovernedStateDomainPhase = Connecting | Live | Stale | ResetRequired | Fatal

GovernedStateUpdate
  = Task(safe update)
  | Approval(safe update)
  | DomainPhase(domain, phase, closed safe reason)
```

R-9B.1 implements only the runtime-agnostic reducer: safe domain state,
independent transition rules, generation fencing, recovery-budget decisions
and atomic per-domain replacement. It does not acquire a baseline, hold a live
session, call a client attachment, schedule a worker or own cancellation.

R-9B.2 adds the shared domain drivers, same-attachment binding, baseline/session
I/O, bounded workers, channel capacity and cancellation. Those drivers must use
the R-9B.1 reducer rather than duplicate its recovery decisions. No new
asynchronous runtime dependency is required for R-9B.1.

## Independent domain lifecycle

Each domain independently reports `Connecting`, `Live`, `Stale`,
`ResetRequired` or `Fatal`.

1. `Live` is entered only after that domain's complete baseline is consumed by
   its matching session.
2. EOF or retryable transport failure makes only that domain `Stale` and uses
   only that domain's bounded reconnect budget.
3. `ResetRequired` is a one-way barrier. The old session is retired. Only the
   affected domain obtains and consumes a new complete baseline.
4. Permission, integrity, protocol, baseline-limit or exhausted-reconnect
   failure makes only that domain `Fatal`.
5. Replay and Heartbeat never mutate governed facts.
6. A failed or partial baseline is never published. The last complete safe
   facts remain visible with the affected domain's non-live state.

A failure, reset, reconnect or fatal stop in one domain cannot stop, clear,
replace, indefinitely delay or falsely downgrade the other domain. Progress in
one domain cannot reset the other domain's recovery budget. Replay,
same-position updates and baseline publication do not count as forward
progress.

## Ordering and correlation

Ordering exists only inside each underlying stream. The coordinator may
interleave ready Task and Approval updates for consumption, but that
interleaving has no governance meaning and is not a total order.

Cross-domain `task_id` association is a read-only display correlation. It is
not proof of causality, atomicity, approval applicability, Task completion or a
shared checkpoint.

## R-9B.1 acceptance gates

R-9B.1 is complete only when component and fault tests prove all of the
following:

1. Task and Approval states retain separate safe facts, phases, read-only
   positions, generations and finite recovery budgets.
2. A Task transition leaves every Approval field unchanged, and an Approval
   transition leaves every Task field unchanged.
3. Initial Task failure can produce Task `Fatal` while Approval becomes `Live`;
   initial Approval failure has the symmetric result. There is no all-or-nothing
   composite initialization rule.
4. EOF, retryable transport failure, `ResetRequired`, permission failure,
   integrity failure, baseline limit and reconnect exhaustion inputs affect
   only the matching domain's deterministic state.
5. Replay, Heartbeat, same-position and stale-generation inputs do not replace
   safe facts or falsely reset a recovery budget.
6. A successful complete-rebaseline input atomically replaces only the
   affected domain. Failed or partial rebaseline inputs preserve its last safe
   facts and the entire other domain.
7. Generation and recovery-budget decisions are deterministic; stale
   generations cannot publish or reset a budget.
8. The reducer performs no I/O and cannot introduce a command RPC, Authority
   write, global cursor, total order or Task-completion inference.

The R-9B.1 change set is limited to this SSOT, the shared Rust reducer and
focused component/fault tests. It does not claim baseline/session integration,
worker behavior, a CLI, a TUI or a real-daemon user flow.

## R-9B.2 and C5 handoff

R-9B.2 first binds the reducer to the two existing baseline/session paths and
the same `ClientAttachment`. Initial permission, baseline or stream-open
failure in one domain must leave the other able to initialize and become
`Live`. It then supplies bounded shared workers so Task progress cannot starve
Approval progress or vice versa, with cancellable receive, send-reserve and
reconnect-delay waits. CLI and TUI consume those same drivers and do not copy
the recovery algorithm. CLI/TUI presentation wording is not frozen here.

The R-9B real-process C5 must cover Windows daemon/IPC, same-root restart,
single-domain disconnect while the other continues, real reset/retention
behavior, independent permission rejection, bounded recovery and read-only
Authority-store evidence.

## Non-goals and forbidden expansion

- no new Proto message, RPC, database, schema migration or Authority writer;
- no global governed-state stream, cursor, epoch, sequence or transaction;
- no R-9C Harness content, raw observation, terminal bytes or redaction policy;
- no Provider routing, Memory/RAG mutation or Desktop work;
- no automatic Task/Run/Step/Attempt transition or Approval action;
- no replacement of the existing Task or Approval stream contracts;
- no claim that the two domain snapshots are simultaneous or atomically
  consistent.

## Exit condition

R-9B is not complete when R-9B.1 passes. It closes only after R-9B.2 and the
real-process C5 evidence also pass. R-9C remains separately blocked on the
Founder disclosure contract for visible content categories, redaction,
retention/replay and terminal-content relationships.
