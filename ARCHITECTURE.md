# EgoPulse implementation architecture

- Status: governed work loop implemented; production admission is held per Provider/Harness route
- Date: 2026-08-27
- Decision owner: Founder

## Source and responsibility

The historical `founder-agent-os` workspace remains the source for research, governance history and frozen architecture decisions. EgoPulse is the implementation repository for new product code, machine contracts, migrations and release artifacts.

No runtime code is copied automatically from the historical workspace. Reuse requires an explicit migration work package with provenance, tests and rollback.

## Dependency direction

```text
Desktop / CLI / TUI
        |
        v
shared Rust client kernel
  +-- exact contract/profile negotiation
  +-- session/request binding
  +-- typed authorization preflight
  +-- stream dedupe + reset/refetch state
        |
        v
Named Pipe / UDS account-authenticated local transport
        |
        v
local session service (ephemeral, policy-resolved)
        |
        v
local read/command API gateway (G4-08C C2/C3)
        |
        v
agentosd deployment host
  +-- cognition-runtime authorities
  +-- local-ide collaboration control
  +-- artifact authority + content-addressed blob data plane
  +-- process supervision
        |
        v
Harness / Worker / Sego adapters
```

`agentosd` is a deployment host, not a shared fact owner. Authority and control modules must retain separate APIs, single-writer storage ownership and audit streams.

Artifact metadata and content-addressed bytes form an independent fact domain. The Rust
`artifact-authority` module owns metadata, immutable sets and technical return receipts; the blob
data plane stores bytes by verified digest. Harnesses and collectors may submit candidates, but
neither receives the Authority database handle nor may a terminal Harness event decide Artifact,
verification or Task completion.

The Artifact Authority `collaboration-control` ReturnReceipt outbox is consumed by the same
single-writer Collaboration runner. It joins the receipt to the consumed Adapter terminal
candidate by `dispatch_id` and sequence, then records Attempt return under the ArtifactAuthority
principal. A digest, lineage, fence, sequence or revision mismatch leaves the receipt pending and
produces no Collaboration write.

The production return path is provider-neutral and durable. A native Harness driver emits one
terminal output candidate; Adapter Edge atomically binds it to the terminal observation, immutable
dispatch envelope and Collaboration-owned Task/work lineage. The governed return collector may
then stage and seal the bytes through Artifact Authority and settle the Adapter outbox only after a
technical `ReturnReceipt` exists. Empty or size-truncated candidates are held for review. This path
does not record an Attempt return, perform verification or commit a Step; those remain explicit
Collaboration/Sego stages after technical evidence intake.

## Language boundaries

| Runtime | Owns | Must not own |
|---|---|---|
| Rust | deterministic authorities, collaboration control, process supervision, local API, CLI/TUI and Tauri bridge | experimental model algorithms |
| TypeScript | Desktop UI, generated client, Agent SDK and bounded native Harness | global Run/DAG authority or Memory truth |
| Python | parsing, embedding, reranking, evaluation and experiments | Task/Memory/Policy/Verdict/Release facts |

## Contract boundaries

- Internal commands/events/API: Protobuf proto3, checked by Buf.
- Artifact and tool boundaries: JSON Schema 2020-12.
- Local client transport: HTTP/2 gRPC over Windows Named Pipe or Unix Domain Socket. The platform crate owns peer-account extraction, owner-only access control and all required platform `unsafe`.
- Local session boundary: account-level peer identity is resolved by a trusted policy adapter into a logical principal and permissions; sessions are process-ephemeral, connection/account-bound, expiring and revocable. An OS SID/UID never implies Founder identity.
- Shared three-surface client kernel: G4-08C C1 provides the independent Rust `client-kernel` crate with digest-bound profiles, surface-neutral session/request state, typed authorization preflight and complete-snapshot replay/reset handling. It does not own facts or final authorization.
- Shared profile interpretation: G4-08C C2 moves digest verification, profile parsing and fail-closed RPC/oneof authorization lookup into the framework-neutral `domain-contracts::profiles` boundary. Client and server consume that one interpreter; framework types still cannot enter `domain-contracts`.
- Local API gateway: G4-08C C2/C3 is exercised by the real CLI/TUI C5 fixtures over Windows Named Pipe; the default production provider bootstrap remains open.
- Supervised Worker/Harness transport: the Codex App Server official native protocol adapter and durable Adapter Edge are implemented for V-01; additional Harness protocols remain separate adapter units.
- Codex production adapter: `crates/codex-adapter` is the only active
  production Harness (admitted for GPT and DeepSeek). It is selected
  through the reviewed capability profile and the governed
  Collaboration/Adapter/Artifact/Verification path.
- Kimi candidate adapter: `crates/kimi-adapter` isolates the Kimi CLI ACP
  session and candidate execution lifecycle behind the same provider-neutral
  driver and process-supervision boundary. It supports candidate prompt,
  update, permission, cancellation and one-shot output extraction, but the
  authenticated lifecycle has not been attested; it is not wired into daemon
  provider selection.
- DSH adapter (admitted for DeepSeek): `crates/dsh-adapter` isolates the DeepSeek Harness
  ACP lifecycle behind the same provider-neutral driver and process
  supervision boundary. Fresh-session prompt, cancellation and a governed
  permission replay are locally verified. Native `session/load`/
  `session/resume` are unsupported and native Artifact semantics are not
  independently attested, so those paths stay degraded and fail-closed even
  though the route is admitted for production work.
- Memory/RAG boundary: `workers/memory-rag` is a dependency-free, read-only
  lexical retrieval implementation behind the frozen `egopulse.memory.v1`
  contract. Rust supplies verified, scoped, already-accepted records; the
  worker returns ranked references and a snapshot-bound evidence digest. It
  has no authority database access and is not the production Memory Authority.
- Generic Worker process framing: `egopulse-process-supervision` provides a
  bounded, supervised one-request/one-response length-delimited stdin/stdout
  boundary for future Workers. It carries opaque bytes and does not freeze
  Memory/RAG messages or serialization choices.
- Memory Authority implementation: `cognition-runtime::memory_authority` is
  the Rust single-writer for local Memory facts. Agent/Model/Harness writes
  enter as `candidate`; only Founder-controlled principals may accept, while
  governance/recovery principals may revoke with evidence. SQLCipher,
  idempotency, optimistic revision checks and an audit event stream remain
  Rust-owned. The approved Worker contract exposes only a bounded accepted
  snapshot; it does not expose authority storage or write operations.
- Multi-Harness composition: `DaemonProviders::with_profiled_native_harness_drivers`
  builds heterogeneous provider-specific runners behind one
  `CompositeHarnessDispatchRunner`. They share the real Task activation source,
  but each runner must be bound to its own reviewed capability profile,
  Collaboration store and Adapter Edge; duplicate per-provider store paths are
  rejected. The exact `ContractReference` route matches profile ID, version
  and SHA-256; an ID-only route is not a supported production API. The
  composite sequences runners and does not choose models or merge
  provider-owned facts. A second and third Harness are admitted only for
  DeepSeek; composition itself admits nothing.
- Task activation routing: the production native composition binds the same
  exact profile reference at activation consumption, Collaboration dispatch
  registration and dispatch selection. Workflow resolution distinguishes an
  explicit `NotApplicable` routing result from resolver failure, so a parallel
  provider runner leaves another route's activation pending without ACK while
  continuing to process its own matching work.
- Profile-bound native composition: `agentosd` exposes one provider-neutral
  native-driver assembly boundary carrying an explicit adapter id, capability
  profile id and protocol fingerprint. Its common storage, workspace, workflow,
  lease and return-path inputs are held by `NativeHarnessCompositionConfig`;
  provider process configuration is kept outside that type. The Codex entry
  point is a compatibility wrapper that adds the Codex executable while the
  user-owned JSON shape remains stable. Supplying a profile or native config to
  this boundary does not grant admission; profile attestation and the
  provider-specific lifecycle evidence remain prerequisites, and each
  Provider/Harness route is admitted separately in the composition
  allowlist, so Kimi, GLM and any unlisted pairing cannot be wired into
  production selection.

## Repository rules

1. UI, Harnesses and Workers never connect to authority databases.
2. Framework types do not enter `domain-contracts`.
3. LangGraph.js remains inside `packages/native-harness`.
4. Python projects remain isolated and cannot become an authority backend.
5. `contracts/` is the only machine-contract source; generated output is never edited as truth.
6. A vertical feature starts only after the Foundation Gate passes.
7. Rust `unsafe` is allowed only inside `crates/local-ipc-platform`; repository boundary checks reject it elsewhere.
