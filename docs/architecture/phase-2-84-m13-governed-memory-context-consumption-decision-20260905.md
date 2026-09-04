# Phase 2-84: M-13 governed Memory context consumption decision

- Date: 2026-09-05
- Status: `recommended_pending_founder`
- Decision owner: Founder
- Integration DRI: Codex main window
- Repository baseline: `a494df68f61e76810ff167f8a385d7acf1a84861`
- Scope: one coherent product capability, not a collection of independent
  feature units

## 1. Decision to make

EgoPulse already governs Memory creation, acceptance, revocation and retrieval,
and already governs natural-language work preparation, Founder confirmation and
Harness dispatch. The missing product behavior is the bridge between them:

```text
accepted Memory snapshot
  -> governed retrieval during PrepareWork
  -> Authority-resolved, bounded MemoryPack
  -> Founder-visible ContextSnapshot preview
  -> exact Founder confirmation
  -> one per-model MemoryUseReceipt before Adapter delivery
```

This is architecture-significant because it determines which owner may expose
Memory content to a model, when user consent becomes durable, what a later
Memory revoke means, and which failure can prevent an external Provider call.
It cannot be inferred from the existence of unused fields or unit-test-only
methods.

M-13 is one end-to-end unit. The numbered clauses below are invariants of that
one decision, not separately scheduled product features.

## 2. Evidence ledger

### Founder-confirmed constraints

- Memory/RAG and multi-model work are required product capabilities.
- Rust owns deterministic control and Memory governance; Python owns
  replaceable cognition algorithms; TypeScript is a surface, not a second
  business kernel.
- CLI and TUI are phase-one surfaces over one shared kernel. Desktop is outside
  this unit.
- Agent, model and Harness output may propose a Memory candidate, but cannot
  accept it or write Memory truth directly.
- Architecture freezes global ownership, trust, recovery and quality
  properties; algorithms, models and tunable retrieval values remain
  replaceable profiles unless they cross those boundaries.

### Formal repository decisions

- M-01 through M-10 freeze accepted-snapshot-only Worker input,
  reference-only Worker output, supervised Protobuf transport, scope
  authorization, typed failure and one shared client capability.
- M-07 through M-10 explicitly excluded automatic Context injection from that
  retrieval unit. Their existence is therefore not authority to enable it.
- Phase 2-55 selected an Authority-owned ContextSnapshot and reserved an
  accepted MemoryPack plus Memory Authority revision and per-model
  `MemoryUseReceipt` as the intended shape.
- R-9A freezes Context revoke/dispatch authorization ordering; R-9C freezes
  governed Harness content disclosure. Neither decision grants a Worker or
  Provider Memory ownership.
- Lexical retrieval remains the admitted production profile. Semantic and
  hybrid candidates remain evaluation-only until a separate measured
  admission decision.

### Current code and runtime facts

- `ConfiguredWorkPreparationPort` always issues `memory_pack: None`; its preview
  returns no Memory revision or pack digest.
- `ConfiguredMemoryRetrievalPort` already owns the one supervised Worker,
  accepted-snapshot read, scope policy, semaphore and response validation, but
  it is not shared with Work Preparation.
- `WorkPreparationPort::prepare` is synchronous while the governed Worker path
  is asynchronous.
- `AcceptedMemorySnapshot` currently carries scope, records and snapshot
  digest, but not one atomically observed Authority revision.
- Context Authority already persists Memory-use receipts, but no production
  dispatch path calls that operation.
- The production Context gate runs after immutable material resolution and
  route validation, but before Adapter `begin_delivery` and native send.

### Independent review reconciliation

- Architecture, implementation and test reviews agree that this is one
  production bridge and is not authorized by the already closed retrieval
  command alone.
- The implementation review identified one necessary mechanical seam:
  Work Preparation must become asynchronous while reusing the existing
  supervised retrieval instance. M13-03 owns that migration; it is not a
  separate feature.
- The test review proposed representing a successful no-match result as no
  pack and no receipt. This recommendation is not selected because it would
  make `DISABLED` and “governed retrieval ran and selected nothing” share the
  same durable fact. M13-05 instead chooses a canonical empty pack, an explicit
  warning and a receipt whose narrow meaning is only that the exact empty pack
  was made available to the governed dispatch. It does not claim that Memory
  influenced model output.
- The entire unit adds one real-process C5 scenario. Normal, empty, denied,
  failure, drift, revoke and replay observations are branches or lower-level
  assertions inside that unit, not separately scheduled development tasks.

## 3. Required user result and quality Gates

| Quality property | Required observable result |
|---|---|
| User control | No Memory bytes reach a Provider unless the exact pack appears in an Authority-owned preview and the Founder confirms that binding. |
| Ownership | Memory Authority remains the only Memory fact writer. The Worker ranks references only; Context Compiler resolves content again. |
| Integrity | Scope, accepted-snapshot digest, record identity/revision/content digest, algorithm identity, query digest and pack digest are mutually consistent. |
| Fail-closed behavior | Requested governed Memory plus Worker/Authority/integrity failure yields no ContextSnapshot, Task, MemoryUseReceipt, Adapter begin-delivery or Provider send. |
| Auditability | Every Memory-bound dispatch has exactly one durable receipt for the exact model route, Attempt, Dispatch, Authority revision and pack digest. |
| Replay/recovery | Ready-dispatch replay may finish only the same transaction; Adapter Replay/DeliveryUnknown performs read-only receipt verification and never reruns retrieval. |
| Bounded local cost | The first profile is finite in result count and content bytes and stays within the existing single Worker and process budget. |
| Replaceability | A later embedding/reranking profile cannot change Authority ownership, the preview/confirmation boundary or receipt semantics. |

## 4. Genuine alternatives

| Candidate | Benefit | Cost / failure | Disposition |
|---|---|---|---|
| Keep retrieval as a separate manual command | Zero contract/runtime change | The normal Agent path still does not use Memory; Memory/RAG remains a diagnostic capability | Rejected for M-13 outcome |
| Client retrieves and submits references or content | Easy to prototype in CLI/TUI | Moves scope, selection and authoritative content across the client trust boundary; creates a second compiler | Rejected |
| Inject at dispatch time | No async change to Work Preparation | Changes model input after Founder confirmation and breaks Context/input digest identity | Rejected |
| Prepare-time governed MemoryPack | Reuses existing owners; Founder sees and confirms the exact bytes before Task creation | Requires one additive request choice, async preparation and a durable receipt join | Recommended |

## 5. Recommended M-13 contract

The following clauses are recommended as one package and remain
`pending_founder_decision` until explicitly confirmed.

### M13-01 — explicit use mode and compatibility

Add one closed `WorkMemoryMode` to `PrepareWorkRequest`:

- `UNSPECIFIED` and `DISABLED` perform the current no-Memory behavior;
- `GOVERNED_RETRIEVAL` requests the admitted read-only Memory path;
- old clients therefore remain no-Memory by default;
- phase-one CLI/TUI may default their new interaction to
  `GOVERNED_RETRIEVAL`, while exposing an explicit no-Memory choice;
- a client cannot select an algorithm, executable, snapshot, record set or
  Authority revision.

Why: this gives the personal Agent an explicit per-work consent choice without
letting a surface author Memory facts. Cost: contract draft.22 and all generated
bindings must advance together.

### M13-02 — one retrieval at preparation

For `GOVERNED_RETRIEVAL`, query bytes are exactly the normalized intent shown
in the preview. Retrieval runs once during `PrepareWork`; Confirm and dispatch
do not rerun or rewrite the query. Model output, file contents and hidden
prompts cannot become an implicit retrieval query.

Why: it binds selection to visible user intent and makes replay deterministic.
Cost: query expansion and agentic retrieval are deferred to a separately
versioned, evaluated compiler profile.

### M13-03 — one shared asynchronous Worker path

Work Preparation reuses the same configured retrieval instance, semaphore,
scope allowlist and `MemoryAuthority` handle used by Local Cognition. Only
`prepare` becomes asynchronous; `confirm` and other command ports stay
synchronous. Blocking a runtime thread with `block_on`, creating a nested
runtime or constructing a second Worker is forbidden.

Why: the current Worker is already the supervised, bounded, validated
production boundary. Cost: the internal Rust Work Preparation trait and its
test doubles must be migrated to async.

### M13-04 — versioned canonical MemoryPack

Rust resolves every returned reference against the exact accepted snapshot and
builds a versioned canonical pack. Its digest covers, using explicit
length-prefixed fields rather than incidental JSON map order:

- format/profile ID;
- scope and Memory Authority revision;
- accepted-snapshot digest;
- algorithm ID, exact query digest, result/score limits and evidence reference;
- each selected record in Worker order: rank, Memory ID, record revision,
  source reference, content digest and exact Authority-resolved UTF-8 content.

The Context snapshot stores the pack binding; compiled immutable context
contains the pack metadata and safely framed reference content. The preview
reuses its existing Memory revision/digest fields and lists selected records as
Memory-owned source facts. Memory content is labelled reference data and cannot
override current intent, tool policy or system policy.

Why: the pack remains reproducible and auditable while the Worker stays
reference-only. Cost: canonical fixed vectors become a compatibility
obligation.

### M13-05 — bounded first profile and empty result

The initial replaceable profile is:

- admitted retrieval algorithm: `lexical-overlap-v0`;
- maximum returned records: `8`;
- minimum score: `0.0` (the lexical implementation already omits no-match
  records);
- maximum total selected content: `65,536` UTF-8 bytes;
- records are never partially truncated; a deterministic rank-prefix is used
  and budget exclusions are reported as preview warnings.

A valid no-match result produces a canonical empty MemoryPack, a preview
warning and a confirmable Context. It is not represented as “Memory disabled”.
Its receipt means the exact empty pack was made available to the dispatch; it
does not claim that Memory influenced model output.

These numeric values are an initial technical/profile baseline, not permanent
architecture. A change requires a profile revision, fixed-vector and quality
evaluation, but not a new Authority or Local API shape.

### M13-06 — failure and no silent fallback

When `GOVERNED_RETRIEVAL` is requested, missing configuration, denied scope,
Worker crash/timeout/busy state, malformed response, snapshot drift or pack
overflow fails preparation before Context issue. The system does not silently
replace the request with `memory_pack: None`, and it performs no automatic
retry. The user may retry or explicitly choose `DISABLED`.

Why: a green preview must truthfully mean the requested Memory behavior is in
the immutable Context. Cost: Memory-dependent work is less available when the
local Worker is unhealthy.

### M13-07 — revision and revoke semantics

Memory Authority returns the accepted snapshot and an Authority state revision
from one owner-controlled read boundary. Revision `1` represents the initial
state and each committed Memory event advances it; no caller reconstructs it
from record revisions.

The selected record bindings are revalidated before Context issue and before
Founder confirmation. Drift before confirmation makes the preview stale and
creates no Task. After confirmation, the ContextSnapshot is immutable: a later
Memory revoke affects new preparation but does not silently rewrite the
already-confirmed pack. To stop a confirmed Context before a new dispatch, the
Founder uses the existing Context revoke operation.

Why: Memory Authority decides which facts are eligible for new contexts;
Context Authority decides whether an exact, Founder-confirmed context may be
consumed. This avoids an implicit cross-database cascade and preserves replay.
Cost: a user seeking immediate withdrawal must revoke the active Context as
well as the source Memory. Automatic cascade is deferred unless real product
evidence justifies a separately designed cross-Authority index and recovery
contract.

### M13-08 — atomic dispatch authorization and use receipt

For a Memory-bound Context, the existing Context Authority transaction commits
the dispatch-consumption authorization and MemoryUseReceipt together before
Adapter `begin_delivery`. The receipt binds:

- exact Context snapshot and revision;
- consumer identity derived from the trusted Provider route profile;
- exact Provider model ID;
- Attempt and Dispatch IDs;
- Memory Authority revision and canonical pack digest.

The Adapter-side authorization result carries and verifies the complete receipt
rather than accepting a boolean. A missing, changed or conflicting receipt
causes zero begin-delivery and zero send. Adapter Replay and DeliveryUnknown are
read-only and must find the already committed pair; they cannot create a
receipt or rerun the Worker.

The receipt proves that the pack was made available to the exact governed
dispatch. Actual external delivery still requires the separate Adapter delivery
receipt; neither record alone claims model influence or Task completion.

Why: both facts already belong to Context Authority and share one SQLCipher
store, so one transaction removes a crash ambiguity without creating a new
Authority. Cost: the existing separate receipt method remains a diagnostic API,
while production dispatch uses the combined operation and its stricter replay
rules.

## 6. Implementation boundary after Founder confirmation

One ordered implementation unit is sufficient:

1. contract truth and generated bindings for `WorkMemoryMode`;
2. atomic accepted snapshot/revision read and canonical pack compiler;
3. async Work Preparation using the existing configured Worker;
4. Context Authority combined authorization/receipt transaction;
5. Adapter proof validation plus shared CLI/TUI controls and rendering;
6. focused component/fault tests, one real daemon CLI/TUI C5, local CI, one
   reviewed commit and push.

No new database, service, vector store, background job, Provider admission,
Desktop workflow or Memory writer is authorized.

## 7. Anti-false-green acceptance inventory

The implementation is not complete unless all of these observable groups pass:

1. contract compatibility, generated Rust/Python/TypeScript bindings and exact
   old-client `UNSPECIFIED -> DISABLED` behavior;
2. canonical pack fixed vectors, accepted-only resolution, scope/digest/revision
   tamper rejection and deterministic bounded selection;
3. valid empty pack versus disabled mode distinction;
4. Worker timeout/crash/busy/integrity failures with zero Context, Task,
   receipt, begin-delivery and native send;
5. stale selected record before confirm with zero Task;
6. one atomic authorization/MemoryUseReceipt commit, exact replay and conflict
   rejection; no receipt for a non-Memory Context;
7. Context revoke-first with zero receipt/send, authorization-first exact replay
   without a new receipt, Worker call or dispatch;
8. restart recovery from durable Context/receipt/Adapter facts, with no
   in-memory-log oracle;
9. CLI and TUI produce the same Memory mode, pack identity, model identity and
   Authority facts through the shared client operation;
10. one real Windows daemon/IPC C5 proving candidate -> Founder accept ->
    prepare -> preview -> confirm -> exact model dispatch -> MemoryUseReceipt,
    while candidate/revoked content and raw Worker payload never reach the
    Provider.

The read-only Context store inspection may expose Memory-use receipt and
idempotency counts for the C5 oracle. This is diagnostic evidence over the
existing Context store, not a new Authority, mutation path or public product
contract.

Existing M-07 through M-12 Worker, governance and restart suites; R-9A Context
linearization tests; R-9C content tests; and the current C5 daemon fixture are
reused. Passing a newly added filtered command that executes zero tests is a
failure.

## 8. Migration, rollback and review triggers

- Proto draft.22 is additive. Older clients omit the mode and retain no-Memory
  behavior.
- Existing Context snapshots have no MemoryPack and retain their current
  semantics. No historical pack or receipt is synthesized.
- Existing Memory and Context SQLCipher tables are sufficient; no third store
  or data backfill is introduced.
- Feature rollback makes new requests `DISABLED`; durable snapshots, receipts
  and audit events are retained.
- Lexical remains the rollback algorithm even after a later semantic profile is
  admitted.
- Reopen this architecture only if measured preparation latency repeatedly
  violates the interaction budget, users require Memory revoke to cascade into
  confirmed Contexts, pack limits routinely exclude relevant records, or a
  semantic profile passes the existing evaluation gate and is proposed for
  admission.

## 9. Founder decision requested

Recommended decision:

> Confirm M13-01 through M13-08 as one governed Memory context-consumption
> contract, including non-retroactive post-confirmation Memory revoke semantics,
> the initial bounded lexical profile and the migration/rollback rules in
> section 8.

Until that explicit confirmation exists, this document remains a decision
candidate and no production contract/runtime edit is authorized by it.
