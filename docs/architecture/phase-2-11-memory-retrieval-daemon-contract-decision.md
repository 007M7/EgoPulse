# Phase 2-11 Memory retrieval daemon contract decision

- Status: `founder_confirmed_implemented_locally_verified`
- Decision owner: Founder
- Prepared: 2026-08-26
- Frozen: 2026-08-26
- Authority: `conversation:2026-08-26:founder-memory-rag-m07-m10-freeze`
- Predecessor: M-01 through M-06, frozen in `egopulse.memory.v1` draft.15

## Frozen decision

EgoPulse exposes authenticated read-only
Memory retrieval from the daemon without turning a UI, Local API gateway or
Python Worker into a Memory fact owner. The Local API contract, authorization
profile, daemon composition, CLI and TUI now implement this boundary.

This is an architecture decision rather than a framework choice: it changes a
long-lived local service boundary, permission model, trust path and failure
semantics used by all client surfaces.

## Evidence ledger

### Founder-confirmed constraints

- CLI, TUI and Desktop are three surfaces over one shared product kernel; their
  capabilities must not diverge merely because their presentation differs.
- Phase one implements CLI and TUI; Desktop follows later.
- Memory/RAG and multi-model work are required product capabilities.
- Rust owns deterministic control and Memory governance; Python owns
  replaceable cognition algorithms; TypeScript does not become a second
  business kernel.
- M-01 through M-06 freeze accepted-snapshot ownership, reference-only Worker
  output, supervised Protobuf transport, the lexical baseline, the replaceable
  algorithm boundary and Rust single-writer persistence.

### Repository and runtime facts

- `ProductionBootstrapConfig` opens one SQLCipher `MemoryAuthority` and installs
  its shared owner handle in `DaemonProviders`.
- `DaemonComposition` currently retains that handle but exposes no Memory read
  or write service.
- `LocalReadModelService` serves durable, rebuildable projections with
  projection positions, cursors, watch/reset and await semantics.
- A Memory retrieval is an on-demand bounded computation over an exact accepted
  snapshot; it is not a durable projection and has no projection cursor.
- `MemoryRagWorker` already performs one supervised request/response exchange,
  and Rust validates the returned algorithm, query digest, snapshot digest,
  references, ordering, scores and evidence shape.
- The authorization profile is fail-closed for unknown permissions and RPCs.
  No Memory retrieval permission or RPC exists today.

### Analysis inference

Putting retrieval in `LocalReadModelService` would give one service two
different consistency and failure models. Putting it in
`LocalCommandGatewayService` would falsely model a read-only computation as an
Authority write. A separate cognition service preserves both existing
meanings, but adds one service and one client capability to maintain.

## Required user result

An authenticated local user invokes the same logical operation from CLI or
TUI:

```text
query + requested scope + result bounds
        |
        v
session and contract validation
        |
        v
server-side Memory scope authorization
        |
        v
Rust Memory Authority accepted snapshot
        |
        v
supervised Python retrieval Worker
        |
        v
Rust response validation
        |
        v
ranked references + snapshot/query/evidence digests
```

Success means the client receives a bounded, deterministic list of accepted
Memory references for the exact snapshot. It does not receive a Memory write
capability, an authority store handle, Worker-supplied authoritative content,
or a projection position.

## Quality scenarios and hard boundaries

| Attribute | Required observable behavior |
|---|---|
| Ownership | Only `MemoryAuthority` materializes accepted records; the gateway and Worker cannot create, accept, revoke or persist Memory facts. |
| Scope isolation | Session permission is necessary but not sufficient. A daemon-owned scope policy must revalidate principal and requested scope before snapshot materialization. |
| Integrity | Rust rejects noncanonical digests, unknown references, snapshot drift, invalid ordering, malformed Protobuf and trailing/truncated frames. |
| Bounded execution | Existing M-01–M-06 limits remain ceilings: 16 KiB query, 2,048 records, 8 MiB content, 64 results, 16 MiB frame and 30-second Worker execution. |
| Cancellation | Dropping or cancelling the RPC must drop the supervised exchange and reap its child process; no partial result is returned. |
| Resource control | The initial daemon permits one active retrieval per configured Memory Worker. Additional calls fail with a typed retryable resource-exhausted result rather than spawning unbounded Python processes. |
| Audit privacy | Audit records contain principal ID, request/correlation ID, scope ref, query digest, snapshot digest, result count, algorithm ID and evidence ref. Raw query and Memory content are excluded. |
| Surface consistency | CLI and TUI call the same RPC through the shared Rust client boundary and differ only in parsing/rendering. Desktop can attach later without a second domain implementation. |
| Replaceability | Embeddings, indexes, rerankers and frameworks stay behind `MemoryRagWorker`; changing them cannot change Local API ownership or permission semantics. |

No latency percentile is frozen in this unit because representative local
corpora and semantic retrieval implementations have not yet been measured.
The hard 30-second timeout is a failure ceiling, not a product latency target.

## Candidates

| Candidate | Why choose it | Cost and what it gives up | Result |
|---|---|---|---|
| Keep Memory internal only | No Local API revision and no new permission surface | CLI/TUI cannot provide the required Memory retrieval capability | Rejected: does not meet the user result |
| Add `RetrieveMemory` to `LocalReadModelService` | Reuses an existing client and service | Blurs durable projection semantics with on-demand computation; positions, watch/reset and projection health no longer describe every method | Rejected: weakens a frozen service meaning |
| Add retrieval to `LocalCommandGatewayService` | Reuses command authorization plumbing | Models a read as a write, invites idempotency/await-token semantics, and suggests an Authority mutation that does not occur | Rejected: wrong ownership and execution semantics |
| Add `LocalCognitionService/RetrieveMemory` | Preserves projection and command meanings; isolates algorithm/dependency failures; supports one surface-neutral capability | Adds a service, permission, endpoint, client accessor, configuration branch and dedicated tests | Recommended |
| Persist retrieval jobs and expose async status | Strong recovery and long-running workflow semantics | Creates a new fact domain, store, lifecycle and cleanup burden before workloads justify it | Held as a future option if bounded synchronous retrieval repeatedly violates its timeout/interaction target |

## Recommended decisions

### M-07 — service boundary

Add a separate unary `LocalCognitionService/RetrieveMemory` RPC. The request
contains normal `ClientRequestMetadata`, query, requested scope, `max_results`
and `min_score`. The client cannot select an executable, algorithm profile,
snapshot digest, record set, model or index.

The response is a oneof of the frozen `egopulse.memory.v1.RetrievalResponse`
and `LocalApiError`. It returns references and evidence only. A later internal
Context Compiler can resolve content again through `MemoryAuthority`; that is
not part of this public retrieval unit.

### M-08 — authorization and disclosure

Add permission `local.memory.retrieve` and an exact RPC rule. The Local API
validates the session, negotiated contract and permission; the agentosd-owned
retrieval port then revalidates the authenticated principal against an
explicit principal-to-scope allowlist before reading the Authority.

The API exposes no candidate/revoked records, raw SQLCipher state, Worker
input record content, store path or process diagnostics. Safe audit metadata
uses digests and references only.

### M-09 — execution and failure semantics

The daemon performs retrieval synchronously over the already supervised
length-delimited Protobuf Worker boundary. The first composition has one
concurrent exchange and no automatic retry: a retry could duplicate resource
cost and hide a deterministic contract failure. The user may retry with a new
request ID after a typed retryable failure.

Error mapping is frozen at the category level:

| Condition | Local API result |
|---|---|
| malformed query, scope or bounds | `INVALID_ARGUMENT`, not retryable |
| missing session/permission or disallowed scope | existing authentication/permission error, not retryable |
| Memory Authority unavailable | `AUTHORITY_UNAVAILABLE`, retryable |
| Worker timeout | `DEADLINE_EXCEEDED`, retryable |
| concurrency ceiling reached | new `RESOURCE_EXHAUSTED`, retryable |
| Worker crash or launch failure | new `COGNITION_WORKER_UNAVAILABLE`, retryable only when execution is proven not to have returned a valid response |
| decode, digest, snapshot, reference or ordering violation | `INTEGRITY_FAILURE`, not retryable automatically |

RPC cancellation must reap the Worker. A crash, timeout or cancellation
produces no partial candidate list and never changes Memory Authority state.

### M-10 — shared surfaces and delivery order

Implement one shared Rust client operation and then expose it in this order:

1. CLI: `memory retrieve` with human and JSON output;
2. TUI: the same operation and fields through a form/result view;
3. Desktop: later, through the same Tauri/Rust client boundary.

All three surfaces are contract-compatible from the first API revision even
though Desktop presentation is deferred. No surface receives a Memory write
command in this unit.

## Implemented slices and verification evidence

1. **Contract revision — complete**: draft.16 revises Local API and the authorization profile, updates
   profile digests and contract provenance, generates Rust/Python/TypeScript
   bindings, and passes Buf compatibility.
2. **Gateway boundary — complete**: a framework-neutral `MemoryRetrievalPort`, session
   and profile validation, typed error mapping, bounded concurrency and a
   privacy-safe audit sink.
3. **Daemon composition — complete**: explicit user-owned Worker executable,
   arguments, working directory, process budget and principal/scope allowlist;
   omit the configuration to remain fail-closed.
4. **CLI vertical — complete**: executes the real RPC over Windows Named Pipe and renders
   references/digests without exposing accepted record content.
5. **TUI vertical — complete**: reuses the same attached client operation and proves output
   parity with CLI.
6. **Failure evidence — complete for this unit**: gateway tests cover
   permission denial and malformed input before Worker invocation; real Worker
   tests cover scope denial, concurrency, crash and timeout; M-01 through M-06
   process tests cover cancellation/reaping, malformed frames, snapshot drift
   and deterministic replay; the M-10 process test starts a real daemon and
   proves CLI/TUI parity over Windows Named Pipe.

## Compatibility, rollback and evolution

- The Local API change is additive, but the negotiated contract reference and
  authorization profile digest must advance together. Older binaries fail
  contract negotiation rather than silently missing the permission rule.
- The existing Task, projection and command services remain unchanged.
- Omitting Memory retrieval configuration leaves the new service fail-closed;
  rollback removes service registration and restores the preceding contract
  profile without migrating Memory data.
- No retrieval result is persisted, so this unit introduces no data migration
  or recovery store.
- Reconsider asynchronous persisted jobs only if measured local workloads
  cannot meet an interactive target within the bounded synchronous model, or
  if retrieval must survive daemon restart as a user-visible operation.

## Explicit non-goals

- Memory create/edit/accept/revoke commands;
- authoritative content returned by the Python Worker;
- embedding, vector index, ANN, reranker or framework selection;
- automatic context injection into Harness dispatch;
- retrieval-result persistence or a new background job Authority;
- Desktop presentation in phase one.

## Founder decision record

Founder confirmed M-07 through M-10:

1. independent `LocalCognitionService` rather than Read Model or Command
   Gateway placement;
2. reference-only public response plus daemon-owned principal/scope policy and
   privacy-safe audit;
3. synchronous supervised execution, one active exchange, typed failure
   categories and cancellation reaping;
4. one shared Rust client operation delivered CLI, then TUI, then Desktop.

The decision authorizes draft.16 and its Rust daemon, CLI and TUI
implementation. Desktop remains presentation-deferred, but its capability
contract is already the same `LocalCognitionService/RetrieveMemory` boundary.
