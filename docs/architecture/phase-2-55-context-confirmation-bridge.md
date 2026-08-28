# Phase 2-55: ContextSnapshot and Founder confirmation bridge

- Date: 2026-08-28
- Scope: frozen CLI/TUI interaction from work preview to governed Task creation
- Status: implementation candidate in progress; contract revision draft.17 is
  generated and locally verified, pending Founder acceptance
- Decision owner: Founder

## Why this package exists

The product interaction baseline already freezes the following sequence:

```text
natural-language intent
  -> context preparation and Work-Start Gate
  -> event-packet preview
  -> Founder confirmation
  -> authoritative Task / Run / Step creation
```

The repository now contains the authority-owned bridge as a candidate
implementation. `PrepareWork` compiles a daemon-owned context snapshot and
returns an Authority-owned preview; `ConfirmWork` accepts only the exact
snapshot binding and delegates Task creation to Task Authority. The generated
cross-language bindings and local contract checks are updated to draft.17, but
the revision remains pending Founder acceptance until the runtime and surface
E2E evidence is complete.

## Evidence from the current implementation

The following facts are verified in the current branch:

1. `director-facade` normalizes intent, compiles explicitly supplied source
   references, evaluates the Start Gate and emits a non-dispatchable preview.
2. `LocalCommandGatewayService.ExecuteTaskCommand` accepts the existing
   `task.v1.CreateTaskCommand`.
3. `ConfiguredTaskCreationGuard` accepts only reviewed work types, input
   snapshot IDs, target scopes and exact acceptance/budget contract references.
4. The daemon resolves the authenticated principal and recomputes the command
   digest; the CLI/TUI do not own Task persistence.
5. The candidate now has a first-class daemon-owned `ContextSnapshot` record,
   `PrepareWork`/`ConfirmWork` RPCs, and equivalent CLI/TUI commands. The
   low-level `input_snapshot_id` path remains available only as a diagnostic
   compatibility seam.

Therefore, sending arbitrary preview text as `input_snapshot_id`, inventing
contract references in the client, or treating a local preview file as an
authoritative snapshot would be a governance regression.

## Boundary that must remain frozen

| Concern | Owner | Client responsibility | Forbidden shortcut |
|---|---|---|---|
| Natural-language intent | Founder / Client Kernel | Submit intent and visible scope | Require protocol fields as the normal entry point |
| Context compilation | Context Compiler / Authority | Display the returned preview | Let a Worker, Provider or UI define authoritative context |
| Snapshot identity and digest | Context Authority | Bind confirmation to the displayed identity | Hashing client text into a fake snapshot ID |
| Task creation | Task Authority | Submit an authenticated confirmation command | Client-side database writes or implicit defaults |
| Provider/model/Harness route | Governance Kernel | Select only admitted options when exposed | Let preview or model output select a route |
| Memory facts | Memory Authority | Consume governed references | Auto-accepting retrieved or generated content |
| Execution observation | Collaboration / Adapter projection | Render resumable state | Treat stdout or a terminal return as Task completion |

## Alternatives

### Option A' — internal Context Authority first, without a public Proto change

Implement the Context Compiler/Authority as an internal Rust owner first. It
persists an immutable context snapshot, derives its identity from the actual
compiled bytes, and exposes only an owner-backed resolver to the existing
dispatch and Task creation seams. The existing `input_snapshot_id` remains an
opaque reference; `FileDispatchMaterialResolver` is replaced or wrapped by a
resolver that proves the referenced snapshot, digest, scope and expiry before
producing dispatch material.

This is an implementation stage, not a complete normal-user surface. It can
prove snapshot persistence, dispatch-time validation, restart/recovery and
Task-side binding without changing generated bindings. A subsequent Local API
prepare/confirm operation is still required if CLI/TUI are to expose the
two-step natural-language flow without making users fill low-level Task
fields.

Why choose it first: it reduces public-contract churn while exercising the
hardest ownership and failure semantics against the existing Authority and
Harness boundaries. It follows the existing Memory pattern: establish the
Rust owner and read boundary before admitting a cross-language/public
consumer.

Cost: the first implementation cannot by itself make `work plan` confirmable
by an ordinary user. A temporary profile or diagnostic command would still be
needed, and that command must not be presented as the final product flow. The
Context Authority schema and internal resolver nevertheless become migration,
recovery and compatibility obligations.

### Option A — first-class ContextSnapshot and two-step confirmation

Add the smallest public contract needed for the already-frozen interaction:

```text
PrepareWork(intent, scope, explicit sources)
  -> ContextSnapshotPreview / GateResult / confirmation binding

ConfirmWork(confirmation binding)
  -> daemon-owned Task.Create
  -> TaskView await token
```

The Context Compiler persists an immutable snapshot (or an immutable,
owner-backed reference to one) with its source/include-exclude ledger and
content digest, scope, visibility/redaction, expiry, acceptance contract,
budget profile, non-goals, deadline, recovery entry, allowed read/write paths,
allowed tools/external resources, and the accepted MemoryPack plus its Memory
Authority revision. Consumption records the required per-model
`MemoryUseReceipt` facts. These are context-governance fields, not model
prompt decoration.
The confirmation command contains the snapshot identity and the exact preview
binding, but not arbitrary contract values or raw credentials. The daemon
resolves reviewed references, rejects an expired snapshot at consumption, and
invokes the existing Task Authority command port. Dispatch must query the
Context Authority rather than trusting the string ID; otherwise the binding is
only documentary.

Why choose it: it makes the existing Founder interaction truthful, gives
replay and expiry semantics a durable owner, and preserves the distinction
between planning, confirmation and Task authority.

Cost: a new V-01 contract revision, generated Rust/TypeScript/Python bindings,
Context Authority storage and migration/recovery tests, plus a new local API
surface. The contract becomes a long-lived compatibility obligation. Context
snapshot schema evolution and retention also become release concerns.

### Option B — daemon-owned reviewed work profiles over existing Task.Create

Keep the public contract unchanged and configure a fixed mapping from a small
set of work types/scopes to already prepared `input_snapshot_id`, acceptance
and budget references. The client would show a preview and then ask the daemon
to submit the existing `CreateTaskCommand` using that mapping.

Why it is attractive: no generated-binding or migration cost, and it can make
one narrowly configured vertical executable quickly.

Cost: it cannot carry the frozen ContextSnapshot semantics (source digest,
visibility, expiry, non-goals and confirmation binding) as a first-class
object. It also makes the natural-language preview only an advisory label
unless a separate durable owner is added. It is suitable only as a temporary
single-profile bootstrap, not as the final product interaction contract. If it
is used temporarily, the preview fingerprint must bind to the request
correlation and profile mapping must fail closed on missing or ambiguous
matches; no silent default may be introduced.

### Option C — client-side local preview file and direct Task.Create

This is rejected. It would move authority facts and snapshot binding into the
CLI/TUI process, create a second source of truth, and make replay, expiry and
cross-surface equivalence unverifiable.

## Recommended decision

The implementation follows Option A' internally and has now added the minimal
public part of Option A as a draft.17 candidate. Do not enumerate application
scenarios in the contract. Freeze only the generic context envelope, ownership,
digest, expiry, confirmation binding and Task-authority handoff.
Application-specific work types, Providers, models, RAG algorithms and Harness
policies remain reviewed configuration or separate contracts.

Any public Proto change must pass the existing Buf lint/breaking baseline,
cross-language code generation, contract manifest and TypeScript/Python/Rust
binding checks before it can be called admitted.

The first implementation slice should be limited to:

1. [x] an Authority-owned immutable context snapshot record and read boundary;
2. [x] a preparation result bound to the exact normalized intent, sources,
   scope, Gate result and snapshot digest;
3. [x] a Founder confirmation command with expiry, idempotency and replay
   checks;
4. [x] daemon-side resolution of reviewed Task creation references;
5. [x] a real CLI/TUI `work prepare` and `work confirm` path over the shared
   Client Kernel;
6. [x] unit evidence proving stale, altered, expired, replayed and
   cross-principal confirmations fail closed;
7. [ ] Authority-backed dispatch resolution, full projection E2E and
   user-visible streaming evidence.

The first slice must not add Provider routing, automatic Memory writes,
semantic RAG selection, raw Harness output to the public contract, or Desktop
workflows.

## Exit evidence required before calling the interaction usable

```text
CLI natural language input
  -> Local API prepare
  -> visible snapshot/gate preview
  -> Founder confirmation
  -> Local API confirm
  -> Task Authority commit
  -> Run/Step creation and projection
  -> CLI/TUI resumable state stream
```

Required evidence includes equivalent CLI/TUI authority facts, confirmation
idempotency, stale/expiry rejection, daemon restart recovery, projection await
and the existing invariant that Harness observations never complete a Task.

Until this evidence exists, `work plan` is a valid preview capability and
`task create` remains a diagnostic/acceptance command, not the normal product
入口.
