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
snapshot binding and delegates Task creation to Task Authority. In the
production composition, the daemon may then settle the resulting Task through
the fixed system-only `ActivateTask` operation for the reviewed workflow. The generated
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
7. [ ] Authority-backed dispatch-material resolution, full projection E2E and
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

## R-7 read-side dispatch binding checkpoint (2026-08-30)

The candidate implementation now carries the Authority-owned context binding
across the existing frozen seams without adding Provider, Memory/RAG or Desktop
scope:

1. work preparation publishes immutable, content-addressed JSON input bundles
   using write, flush, file sync and no-overwrite final publication;
2. workflow resolution accepts only canonical `ctx:<sha256>` Task snapshot
   references, proves current scope and Authority state, and binds every
   planned step plus dispatch material to `ctx-<sha256>.json`;
3. the Task activation reference guard proves that the Task, plan and material
   still carry that exact binding;
4. immediately before native Harness dispatch, the material resolver rechecks
   Authority existence, expiry, revoked state and compiled-byte integrity;
5. malformed `ctx-*` references fail closed and never fall back to static file
   material, while ordinary reviewed static bundles remain compatible.

The reviewed `RunPlan.digest_sha256` is retained when a Context-backed Task is
instantiated. In the current repository it is a complete SHA-256-shaped
identity for the reviewed plan/configuration artifact; no contract defines or
validates it as a canonical hash over mutable `RunPlan` fields. The dynamic
instance is instead sealed by the Context/Task bindings, reference guard,
material digest and canonical command request digest. Reinterpreting the plan
digest as an instance-content hash would require a separately frozen
canonicalization, calculation and validation contract.

R-7 is therefore a read-side governance closure, not the whole interaction
closure. At the R-7 checkpoint, both a formal Context Authority revoke write
operation and a real dynamic prepare-to-native-driver CLI/TUI E2E remained
required. R-8A below closes only the latter single-process happy path.

## R-8A real dynamic product E2E checkpoint (2026-08-30)

R-8A now proves the existing architecture across a real daemon and Windows
local IPC without adding Proto, Provider, Memory/RAG or Desktop scope. A CLI
prepares an Authority-owned dynamic context; a TUI confirms the exact binding;
Task Authority commits and activates the Task through the daemon-only system
path; the durable activation handoff creates one Collaboration Run, Step,
Attempt and DispatchIntent; and the production Context-bound material resolver
revalidates the snapshot before one fake native driver is reached through the
real Adapter Edge.

The E2E asserts all dispatch identities, the content-addressed bundle name,
the envelope and byte digests, the governed workspace reference, the compiled
prompt, one-only delivery, and one persisted non-terminal acknowledgement.
It also asserts that the Task remains `Active`. The fake driver implements the
existing native-driver contract and does not bypass Collaboration Control,
dispatch-material resolution or Adapter Edge.

The test exposed and fixed a production integration defect: Work Preparation
had copied Task Authority's canonical request-digest logic and its activation
copy failed to clear correlation and causation metadata. Work Preparation now
calls the Task Authority-owned `canonical_request_digest` oracle for both
CreateTask and ActivateTask. Component evidence verifies that tracing metadata
does not change either request identity, while semantic Task fields do.

This is not a restart or recovery claim. R-8B must separately prove durable
resume and no duplicate external delivery across daemon termination, and the
formal Context revoke write contract remains R-9. User-visible resumable
streaming and the later Artifact/Verification/Founder-verdict closure also
remain open.

## R-8B.1 pre-delivery crash replay checkpoint (2026-08-30)

R-8B.1 adds a real daemon crash/restart acceptance path without changing the
public contracts. A test-only wrapper around the existing production
`HarnessDispatchRunner` records completion of its first empty cycle; it does
not alter the cycle result or any Authority fact. The fixture then delays the
next cycle, commits the normal CLI Prepare -> TUI Confirm -> daemon activation
path, proves that no driver call occurred, and force-terminates the process.

Reopening the same Task, Context, Collaboration, Adapter and read-model stores
with the same reviewed configuration consumes the durable activation handoff
and produces one original dispatch. The E2E verifies stable Run/Step/Attempt/
Dispatch identity, one Adapter dispatch, one governed non-terminal Ack and a
still-`Active` Task.

This closes only the unconsumed activation-handoff restart window proven
here. R-8B.2 must still rebuild recovery work from durable Adapter and
Collaboration facts when delivery is unknown or already recorded. It must
bridge `delivery_unknown` into typed
OutcomeUnknown/Reconciliation/Hold processing, drain pending observations,
and restore Task recovery settlement without using runner memory or logs.
R-8B.2 must never call `send_dispatch` again for a delivery-unknown or delivered
dispatch, and it does not require a Proto change under the current contracts.

## R-8B.2a/b governed delivery-unknown recovery checkpoint (2026-08-30)

R-8B.2a freezes, and R-8B.2b implements, the internal recovery bridge for a
dispatch whose external-delivery result is no longer safe to infer from process
memory. The bridge does not change Proto and does not give Adapter Edge authority
to mutate Collaboration state. Adapter Edge remains the durable owner of the
dispatch envelope, delivery receipt, native reconciliation evidence and the
Collaboration-owned Task lineage bound to that dispatch. Collaboration Control
remains the single writer for Run, Step and Attempt recovery transitions.

The production runner now reconstructs held work from durable Collaboration
outbox facts and validates Adapter evidence through a typed resolver. An Unknown
receipt is accepted only when Adapter identity, dispatch, attempt, fencing token,
capability profile, envelope and Task/work lineage all match the current
Collaboration snapshot. Unknown ingestion idempotently commits
`OutcomeUnknown`; recovery begins reconciliation once, records a durable
conservative disposition, and replays that evidence after restart. A
`Reconciling` attempt without durable evidence remains held and does not repeat
the native reconciliation call.

The frozen disposition mapping is deliberately conservative:

- `NoEffectProven` remains `NoEffectProven` and only makes a future governed
  retry eligible; it neither redispatches nor creates an Attempt;
- `NativeExecutionActive`, `TerminalObservationRecovered` and `OutcomeUnknown`
  become `ManualOnly` holds;
- `ResumeSafe`, `ReturnFound`, `RetryIdempotent` and `IrreversibleUnknown` are not
  emitted by this slice.

Only a durable `Delivered` receipt may enter observation polling. `Unknown`
becomes held; a missing receipt, `Rejected`/`ProvenNotSent`, or any other
non-Delivered value cannot call `next_event`. Receipt replay also cannot call
`send_dispatch` again. Held and terminal dispatch identities are separate, and a
stable Task recovery finding can interrupt the Task through Task Authority but
can never complete, accept, verify or release it. `NoEffectProven` leaves the Run
active and produces no Task interruption.

The local production-component evidence covers Unknown receipt creation from a
`begin_delivery` record with no receipt, zero resend and zero observation pump,
single native reconciliation with durable replay, conservative Task settlement,
Rejected replay without resend/pump, and fail-closed Adapter-ID, fencing-token
and Task-lineage tamper cases. This is not yet the complete R-8B.2 claim.
R-8B.2c must still prove the same invariants with a real Windows daemon hard kill
and same-root/same-instance restart, and must separately rebuild polling for a
dispatch that already has a durable Delivered receipt. Canonical outbox-payload
and receipt-digest recomputation remain integrity hardening beyond the current
controlled Adapter/Collaboration store trust boundary.
