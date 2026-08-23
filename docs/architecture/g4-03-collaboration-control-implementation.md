# G4-03 Collaboration Control implementation profile

- Status: active Gate 4 work package
- Date: 2026-08-23
- Frozen inputs: C-02 Collaboration Contract, C-08 Persistence/Recovery Contract, Feature ADR A
- Scope: durable Run/Step/Attempt authority through `dispatch_pending`, plus fail-closed unknown-outcome recovery

## Boundary

`local-ide-control::collaboration_control` owns the V-01 Collaboration store and is the only module allowed to mutate Run, Step, Attempt, lease or dispatch intent. Its SQLCipher connection and schema stay private. Task Authority, Local API, UI, Harness Adapter, workers and recovery coordination receive commands or owner APIs, never a database handle.

The Collaboration store is physically separate from the Task Authority store. Cross-authority facts arrive through validated references/receipts and leave through durable outbox messages; no module may join or directly query the other owner's tables.

## Why this is an Authority, not a queue

A queue can express pending/claimed/acknowledged delivery, but cannot prove whether an external Harness executed, produced side effects, returned an artifact, or disappeared after an ambiguous call. C-02 therefore requires three related but distinct facts:

```text
Run aggregate revision
  -> Step entity revision
       -> Attempt entity revision + lease/fence + dispatch identity
```

Every successful command increments the Run revision. A changed Step or Attempt also increments its entity revision. This gives a global commit order plus local CAS protection without treating a process, terminal window or native Harness session as the owner.

The cost is more states, events and recovery branches than a conventional queue. That cost is paid whenever a receipt is late, a lease expires, or a process dies; in return, unknown external effects cannot silently become an automatic retry.

## Persistence choice

Use the same exact `rusqlite 0.40.2` + `bundled-sqlcipher-vendored-openssl` and `rusqlite_migration 2.6.0` baseline already accepted and fault-tested for G4-02, but in an independent Collaboration database and schema profile.

Why this choice:

- C-08 freezes local SQLCipher, explicit owner transactions and an atomic state/event/idempotency/outbox boundary.
- Collaboration Control is a single writer. A synchronous connection on its serialized lane exposes CAS, fencing and durability controls directly.
- Reusing the exact Gate 3/G4-02 SQLCipher build profile avoids a second encryption/linkage stack and prevents plaintext system-SQLite fallback.

What this gives up and where the cost appears:

- The bundled SQLCipher/OpenSSL build, patch, license and debug-symbol costs remain; this is deliberate reuse, not a claim that they disappeared.
- A synchronous owner lane limits write concurrency. Later Local API integration must enqueue owner commands rather than hold async executor threads in arbitrary database work.
- Separate Authority stores prohibit convenient cross-domain SQL joins. Consumers must use receipts/outbox/inbox, increasing protocol work but preserving ownership and independent recovery.
- A general workflow engine or broker was not selected: neither can atomically include this local Authority's revisions and encrypted owner facts, and both would introduce a second scheduler/source of truth.

## Durable dispatch invariant

`RecordDispatchIntent` performs one owner transaction containing:

1. updated Run, Step and Attempt snapshots;
2. one append-only `DISPATCH_INTENT_RECORDED` event;
3. the command idempotency result;
4. a local read-model outbox message;
5. a Harness Adapter outbox message whose payload is the frozen provider-neutral `DispatchEnvelope`;
6. commit receipt and domain watermark.

Only after this transaction commits may an adapter poll/receive the pending dispatch. If the daemon crashes before delivery, the same message ID and envelope remain pending after reopen. A duplicate command replays the original result and cannot create a second dispatch.

The dispatch envelope is assembled by the Authority from committed Run/Step/Attempt facts plus trusted policy material. Caller-supplied `dispatch_id`, fence and fingerprint must match the canonical envelope; the caller cannot inject policy or workspace authority through a request body.

## Lease and unknown outcome

- Lease time comes from the Authority clock and a validated lease policy; caller `issued_at` is not the lease clock.
- Each acquire creates a new lease ID and strictly increasing fencing token.
- Dispatch requires the current unexpired lease ID/token. A stale token has zero business writes.
- Lease expiry revokes write authority but does not prove the external process stopped.
- A dispatch with uncertain external effect transitions Run/Step to `held` and Attempt to `outcome_unknown`. It emits recovery evidence but no retry dispatch.

## G4-03 implemented mutation subset

G4-03 implements `CreateRun`, `ActivateRun`, `CreateAttempt`, `AcquireAttemptLease`, `RecordDispatchIntent` and `MarkAttemptOutcomeUnknown`. Later delivery, ACK, lifecycle, cancellation, reconciliation, checkpoint and return mutations remain fail closed until their owning work packages provide C-03/C-04 evidence. This keeps G4-03 from pretending that the adapter path already exists.

## Exit tests

- valid one-Step Run creation/activation and dual CAS revisions;
- one active Attempt capacity and stale Run/Step/Attempt revision rejection;
- Authority-clock lease acquisition and stale/expired fence rejection;
- dispatch intent committed before a provider-neutral envelope becomes pollable;
- duplicate dispatch intent replay with zero additional state/event/outbox writes;
- process abort after dispatch commit/before delivery, followed by pending outbox recovery;
- lease-expired ambiguous execution to `outcome_unknown`/held with no retry message;
- encrypted close/reopen integrity and dependency boundary checks.
