# Phase 2-55: ContextSnapshot and Founder confirmation bridge

- Date: 2026-08-28
- Scope: frozen CLI/TUI interaction from work preview to governed Task creation
- Status: decision package; implementation not yet admitted
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

The current repository implements the first three items as a pure Director
preview and implements the low-level `Task.Create` command separately. It does
not yet contain the authority-owned bridge between those two surfaces. This
document records that fact and the implementation decision that must precede a
public contract change.

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
5. `input_snapshot_id` is currently an opaque, allowlisted reference. There is
   no first-class `ContextSnapshot` message, durable context owner, or
   two-step preview/confirmation RPC.

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
owner-backed reference to one) with its source/digest, scope, visibility,
expiry, acceptance contract, budget profile, non-goals and recovery facts.
The confirmation command contains the snapshot identity and the exact preview
binding, but not arbitrary contract values or raw credentials. The daemon
resolves reviewed references and invokes the existing Task Authority command
port.

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
single-profile bootstrap, not as the final product interaction contract.

### Option C — client-side local preview file and direct Task.Create

This is rejected. It would move authority facts and snapshot binding into the
CLI/TUI process, create a second source of truth, and make replay, expiry and
cross-surface equivalence unverifiable.

## Recommended decision

Admit Option A as the implementation of the already-frozen architecture. Do
not enumerate application scenarios in the contract. Freeze only the generic
context envelope, ownership, digest, expiry, confirmation binding and
Task-authority handoff. Application-specific work types, Providers, models,
RAG algorithms and Harness policies remain reviewed configuration or separate
contracts.

The first implementation slice should be limited to:

1. an Authority-owned immutable context snapshot record and read boundary;
2. a preparation result bound to the exact normalized intent, sources, scope,
   Gate result and snapshot digest;
3. a Founder confirmation command with expiry, idempotency and replay checks;
4. daemon-side resolution of reviewed Task creation references;
5. a real CLI/TUI `work confirm` path over the shared Client Kernel;
6. tests proving stale, altered, expired, replayed and cross-principal
   confirmations fail closed.

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
