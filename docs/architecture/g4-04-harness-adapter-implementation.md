# G4-04 Harness Adapter implementation profile

- Status: G4-04 accepted; production composition, authenticated provider-boundary and
  Verification-gated Return settlement evidence complete
- Date: 2026-08-27
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
- a terminal `ExecutionCompleted` observation and its provider-neutral output candidate are written
  atomically to Adapter Edge; the observation is not marked consumed until the candidate has a
  durable handoff path;
- Collaboration binds its authoritative Task ID, Task revision and work revision after the dispatch
  envelope is durable and before terminal observations are pumped. Adapter Edge rejects missing,
  conflicting or corrupt lineage rather than inferring it from provider data;
- terminal output storage is bounded: complete values up to 16 MiB are retained, while larger values
  retain a 64 KiB preview, full-content digest, original byte count and an explicit incomplete marker;
- output outbox acknowledgement requires the exact payload digest and occurs only after Artifact
  Authority has emitted a technical return receipt. Empty and incomplete candidates are held;
- reconciliation probes restore the immutable dispatch and native execution binding by
  `dispatch_id`, then persist a provider-neutral diagnostic observation and encrypted raw evidence;
- `(dispatch_id, reconciliation_id)` is idempotent across process restart: replay resolves the same
  evidence ID without another native reconcile call;
- the Adapter-backed evidence resolver verifies delivery, ACK, running, structured interruption and
  reconciliation evidence from the independent Adapter SQLCipher edge before Collaboration writes;
- the return projection resolver verifies an Artifact Authority ReturnReceipt against its encoded
  digest and joins it to the consumed Adapter terminal candidate by dispatch, fence and observation
  sequence before Collaboration records Attempt return;
- the integrated fake-Harness path now proves committed outbox consumption, delivery, ACK, running,
  terminal-candidate deferral, cancellation confirmation and `outcome_unknown -> reconciling ->
  interrupted/retry-idempotent` recovery from a matching `no_effect_proven` finding without leaking
  native execution references into Collaboration;
- Adapter evidence identity alone cannot authorize a caller-selected recovery disposition. The
  resolver currently permits only `no_effect_proven -> no_effect_proven`; recovered terminal,
  active-execution and outcome-unknown findings require the appropriate Artifact, checkpoint,
  side-effect or human authority before C-02 may advance.

## Production composition audit

The production composition root and its authenticated Codex provider-boundary
evidence are complete for the first production Harness:

- `apps/agentosd/src/bootstrap.rs::ProductionBootstrapConfig::build` opens
  the owner Authorities, installs optional Verification and Memory/RAG
  workers, and then calls `DaemonProviders::with_codex_harness`;
- `apps/agentosd/src/lib.rs::DaemonProviders::with_codex_harness` opens the
  reader and writer Adapter Edge handles, constructs Collaboration Control,
  the Codex native driver and the `GovernedTaskActivationRunner`, then exposes
  exactly that runner to the daemon background worker;
- Kimi and DSH crates are not referenced by the production bootstrap and
  cannot become a production provider through a candidate-only constructor;
- the C5 real-process fixture proves local IPC, CLI/TUI shared operations and
  Memory retrieval;
- the provider-neutral Codex contract test proves the native app-server
  lifecycle and protocol observations;
- the user-configured production runner test proves that the same composition
  boundary can activate a Task, consume the Collaboration workflow, durably
  dispatch through Adapter Edge and complete a real Codex request.

The authenticated live adapter contract probe was re-run locally on Windows x64
on 2026-08-26 with Codex CLI `0.148.0-alpha.15` after correcting one adapter
classification defect:

```powershell
$env:EGOPULSE_CODEX_NATIVE_EXE =
  'C:\Users\Administrator\AppData\Roaming\npm\codex.cmd'
cargo test -p egopulse-codex-adapter --test provider_neutral_contract live_codex_app_server_emits_contract_valid_ack_running_and_terminal_observations -- --ignored --nocapture
```

The test passed and observed native session/turn lifecycle, accepted ACK,
running and terminal observations, approval requests, control acknowledgements
and cancellation/recovery-related lifecycle evidence. It used an isolated
adapter edge and did not alter the repository. The native
`mcpServer/startupStatus/updated` status `cancelled` is now recorded as an
informational diagnostic rather than a dispatch recovery signal; actual
`failed` startup remains recovery-required. This closes the missing live Codex
protocol evidence for the adapter runtime; it does not claim that the full
user-owned production bootstrap and background runner have been exercised by
the same test.

The Codex driver now treats an unresolved native approval request as a clean
observation-stream handoff: the dispatch worker returns control instead of
blocking on a response that requires a separate `decide_approval` call. The
production runner now retains the active immutable dispatch envelope across
cycles, continues pumping it after the approval authority responds, and
releases it only after a terminal observation. This is an execution-lifecycle
fix, not approval authorization.

The Codex driver also reconstructs one terminal `agentMessage` candidate from
native item completion or streamed deltas. This candidate is one-shot at the
driver boundary and durable at Adapter Edge, so runner restart cannot fabricate
a second logical return. DSH and fake drivers implement the same provider-neutral
candidate seam; production Harness selection remains unchanged.

The user-configured production runner was then exercised on Windows x64 with
the installed Codex native executable. The fixture now covers the complete
non-terminal production return slice:

```powershell
$env:EGOPULSE_CODEX_NATIVE_EXE =
  'C:\Users\Administrator\AppData\Local\OpenAI\Codex\bin\<installed>\codex.exe'
cargo test -p egopulse-agentosd --test production_runner_g4_04 `
  user_configured_production_runner_completes_real_codex_dispatch `
  -- --ignored --nocapture
```

The test passed in 30.94 seconds and observed Task activation, the governed
Collaboration workflow, Adapter durable dispatch and receipt, Codex
`initialize`, `thread/start`, a real authenticated request, terminal output
collection, Task evidence submission, Verification request intake, deterministic
checker execution, Verification write-back, and one Verification-gated
Step/Run return settlement. The report asserts `return_settlements == 1`.
The fixture derives the user configuration from the published template but binds
the capability profile to the exact Codex contract
`codex-app-server-v2-0.148.0-alpha.15`; the template's `replace-*` values must
never be used as production authorization references. The test-only activation
transition guard is a fixture seam and is not a public activation bypass.

The production path uses a narrow configured Task transition guard for internal
Collaboration and Verification handoffs. It accepts only reviewed non-terminal
Activate, SubmitTaskEvidence and RecordTaskVerification transitions; unsupported
or terminal Founder transitions remain fail-closed until their own authority
vertical is admitted.

This closes the Codex production slice of G4-04. DSH ACP remains a candidate
execution slice documented in Phase 2-09 and cannot be selected by production
configuration until its own authentication, recovery and provider-boundary
evidence is accepted.
