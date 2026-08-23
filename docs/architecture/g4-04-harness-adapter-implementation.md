# G4-04 Harness Adapter implementation profile

- Status: active Gate 4 work package
- Date: 2026-08-23
- Frozen inputs: C-03 Harness Adapter Contract, D-01 first Harness decision, ADR 0003
- First native Harness: Codex app-server v2

## Stable authority split

Collaboration Control remains the only writer of Run, Step and Attempt facts. A Harness Adapter owns
native protocol connections, opaque native session/execution references, delivery evidence and its
encrypted durable edge. It returns only provider-neutral receipts and candidate observations.

```text
Collaboration Control                         Harness Adapter
---------------------                         ---------------
Run / Step / Attempt authority                native protocol + credentials
lease / fencing token                         opaque session / execution refs
dispatch intent + recovery class    <------>  delivery / ACK / raw evidence
verified opaque session ref only              cancellation delivery + reconcile probe
```

Neither side reads the other's database. Evidence crosses the boundary through generated C-03
contracts and a provider-neutral evidence resolver. Codex thread, turn, item and JSON-RPC shapes
remain private to `crates/codex-adapter`.

## Dispatch identity and native execution binding

The frozen Protobuf remains unchanged. The public cancellation workflow addresses an execution by
`dispatch_id`; callers do not supply or govern provider-native routing values. The Adapter resolves
the original immutable dispatch envelope/receipt and the durable ACK observation inside its own
edge, then constructs the existing `CancelExecutionEnvelope` for the native driver.

This is an architectural ownership decision, not a Codex-specific convenience:

- `dispatch_id`, Attempt identity and fence are Collaboration-owned references;
- native session/execution references are Adapter-owned opaque data;
- Collaboration may retain a verified opaque session reference for continuity but never interprets
  it or uses it as the global execution identity;
- failure to resolve both native references fails closed and does not send a cancellation.

The cost is an additional Adapter lookup and durable-edge recovery obligation. It avoids leaking
provider identifiers into Collaboration commands and keeps a second Harness replaceable.

## Cancellation and reconciliation are separate facts

Cancellation follows four explicit boundaries:

1. `RequestAttemptCancellation` commits `cancellation_pending` and holds an undelivered dispatch.
2. Adapter cancellation delivery records only whether the native control request was delivered,
   rejected or uncertain.
3. A verified terminal observation or deadline outcome records cancelled, return-found or
   outcome-unknown. Delivery alone never confirms cancellation.
4. Outcome-unknown remains held until a separately identified reconciliation records return found,
   no effect, retry-idempotent, resume-safe, compensate, manual-only or irreversible-unknown.

The reconciliation ID is checked against the latest durable `RECONCILIATION_STARTED` event. A stale
or mismatched result is a zero-write state conflict. Recovery classification never creates a retry
dispatch by itself.

## Implemented evidence

- fake and real Codex drivers use the same provider-neutral Adapter runtime;
- Adapter SQLCipher edge durably stores dispatch receipts, raw observations, cancellation receipts,
  monotonic observation sequence and conflict quarantine;
- delivery, ACK and running are separate monotonic Collaboration commits;
- ACK-before-delivery, stale fence and out-of-order sequence fail with zero authority writes;
- cancellation pending, cancellation outcome unknown, reconciliation start and reconciliation
  result are distinct durable Collaboration facts;
- cancellation by `dispatch_id` resolves native routing only inside the Adapter;
- duplicate dispatch/native observation/cancellation operations replay without a second native call.
- Adapter candidate facts are delivered at least once and remain pending until Collaboration commits,
  explicitly defers them, or requests Adapter quarantine;
- source replay is bound to durable source evidence, so a crash after authority commit cannot create a
  second fact and reuse of a source ID with another digest is quarantined with zero authority writes;
- stale dispatch/fence candidates are quarantined before authority writes;
- unknown control/security/terminal/artifact candidates hold the Attempt as `outcome_unknown` and
  require Adapter quarantine;
- cancellation is confirmed only by a structured interruption observation while cancellation is
  pending; cancellation delivery is not treated as execution termination.
- reconciliation probes restore the immutable dispatch and native execution binding by
  `dispatch_id`, then persist a provider-neutral diagnostic observation and encrypted raw evidence;
- `(dispatch_id, reconciliation_id)` is idempotent across process restart: replay resolves the same
  evidence ID without another native reconcile call;
- the Adapter-backed evidence resolver verifies delivery, ACK, running, structured interruption and
  reconciliation evidence from the independent Adapter SQLCipher edge before Collaboration writes;
- the integrated fake-Harness path now proves committed outbox consumption, delivery, ACK, running,
  terminal-candidate deferral, cancellation confirmation and `outcome_unknown -> reconciling ->
  interrupted/retry-idempotent` recovery from a matching `no_effect_proven` finding without leaking
  native execution references into Collaboration;
- Adapter evidence identity alone cannot authorize a caller-selected recovery disposition. The
  resolver currently permits only `no_effect_proven -> no_effect_proven`; recovered terminal,
  active-execution and outcome-unknown findings require the appropriate Artifact, checkpoint,
  side-effect or human authority before C-02 may advance.

The concrete resolver composition currently lives in the G4-04 integration harness. The production
daemon composition root is deliberately deferred to G4-08; the production ports and durable Adapter
read APIs are already present. G4-04 remains open only until the complete fake/real contract and
provider-boundary audit is closed.
