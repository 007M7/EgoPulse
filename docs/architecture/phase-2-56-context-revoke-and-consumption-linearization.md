# R-9A Context revoke and dispatch-consumption linearization

- Status: R-9A complete; Founder-frozen contract and Gates 1 through 12 locally verified
- Date: 2026-08-31
- Decision owner: Founder
- Runtime fact owner: Context Authority
- Scope: R-9A only

## Decision

R-9 is split by fact ownership and disclosure risk:

1. **R-9A** adds formal Context revocation and durable authorization for one
   exact dispatch to consume one Context snapshot.
2. **R-9B** will add a resumable stream of governed state projections.
3. **R-9C** will add a resumable, redacted stream of user-visible Harness
   content.

Capability-profile revocation is not part of R-9. It has a different fact
owner and requires a separately frozen Harness Registry write contract.

R-9A retains Context Authority as the only writer of Context facts. It adds an
authenticated Founder-owner revoke command and an internal GovernanceKernel
dispatch-consumption authorization command. Revoke and authorization are
serialized in the same Context Authority store so their commit order is the
only answer to the revoke-versus-send race.

## Why this choice

The existing pre-dispatch Context resolve is a necessary integrity check but
cannot by itself close a check-then-send race: revocation can commit after the
read and before the Adapter side effect. A durable, dispatch-specific
authorization committed in the same write domain as revocation supplies one
auditable linearization point.

Keeping `state_revision` separate from the immutable snapshot revision avoids
redefining the snapshot ID, descriptor, compiled bytes or content digest when
governance state changes. Separating governed-state streaming from redacted
Harness-content streaming prevents R-9A from silently deciding retention,
redaction or terminal-content semantics owned by later slices.

The costs are one Context Authority write before every new dispatch, additional
idempotency and audit records, a store migration, and two revisions that must
never be conflated. An authorization that wins the race remains valid for its
exact dispatch after a later expiry or revoke and has no independent TTL.
Existing Attempt lease/fencing and Adapter at-most-once delivery remain its
execution bounds. Revocation is therefore prospective, not retroactive.

## Authority and dependency boundaries

| Fact or action | Single writer / owner | Consumers | Forbidden ownership |
|---|---|---|---|
| Snapshot descriptor, bytes and content digest | Context Authority | Work preparation, confirmation, activation, dispatch material and governed recovery | Client, Task, Collaboration, Adapter, Harness |
| Context governance state and `state_revision` | Context Authority | Local API, preparation/confirmation, activation, dispatch and recovery | UI, daemon composition, raw SQL callers |
| Revoke command and event | Context Authority, invoked by the authenticated snapshot Founder owner | Local API projection/audit | GovernanceKernel, Task, Collaboration, Adapter |
| Dispatch-consumption authorization and event | Context Authority, invoked only by GovernanceKernel | Governed dispatch path and Adapter verification | Founder client, CLI/TUI, Provider, Harness |
| Run/Step/Attempt facts | Collaboration Control | Runners and read model | Context Authority, Adapter |
| Task status | Task Authority | Collaboration and read model | Context revoke, receipt, observation or recovery seam |
| Delivery receipt and at-most-once native delivery | Adapter Edge | Collaboration and recovery | Context Authority |

`agentosd` composes these owners but does not become an owner. CLI and TUI use
the shared Rust client attachment and never receive an Authority store handle.

## State model

Snapshot content and governance state are distinct:

```text
immutable snapshot
  snapshot_id + snapshot_revision + descriptor + compiled bytes + content digest
  never changes during R-9A

governance state
  Issued(state_revision = n)
      |
      | authenticated Founder owner revoke, expected_state_revision = n
      v
  Revoked(state_revision = n + 1)       terminal

expiry
  derived from the immutable expires_at value; it blocks every new
  consumption authorization but is not a stored replacement for Issued or
  Revoked. An expired Issued snapshot may still be formally revoked by its
  authenticated Founder owner so the governance fact is recorded.
```

The store migration is atomic and forward-only. Before upgrading a store that
may contain Context facts, release/install tooling must preserve a consistent
stopped-daemon backup of the encrypted database and its SQLite sidecars. The
new binary assigns existing rows `state_revision = 1` and updates the schema
digest without rewriting descriptors or compiled bytes. An older binary must
reject the migrated digest; rollback means stopping the daemon and restoring
the complete pre-migration backup with its matching binary, key configuration
and store epoch. There is no in-place down migration and no reinterpretation of
post-upgrade revoke or authorization facts by an older binary.

Dispatch-consumption authorization has its own monotonic lifecycle:

```text
Absent
  | GovernanceKernel command for one exact tuple while Context is Issued,
  | unexpired, scope-valid and byte-integrity-valid
  v
Authorized(snapshot_id, attempt_id, dispatch_id, input_digest_sha256)
  terminal and replayable; never transferable to another tuple; no separate
  TTL. Expiry or revoke after its commit does not invalidate this exact grant.
```

There is no `Revoked -> Issued`, authorization withdrawal, or client-authored
authorization transition in R-9A.

## Linearization contract

Revoke and dispatch authorization must execute as serializable Context
Authority write transactions against the same snapshot governance row. Both
must validate idempotency and integrity inside that transaction. A read check
followed by an unrelated insert is not sufficient.

The authorization transaction conditionally inserts one immutable
authorization only if the snapshot is currently `Issued`, its
`state_revision` equals the expected revision, it has not expired, its scope
and bytes are valid, and the exact authorization tuple is not bound to
different content. Authorization does not increment `state_revision`; it
records the state revision it observed. The revoke transaction conditionally
changes `Issued` to `Revoked` and increments `state_revision` exactly once.
Revoke does not require the Issued snapshot to be unexpired: expiry blocks
consumption, not the recording of a later Founder-owner governance fact.

The durable commit order defines behavior:

| Commit order | Required result |
|---|---|
| Authorization commits before revoke | That exact dispatch may continue. A later revoke cannot invalidate its authorization. Adapter Edge still guarantees at-most-once native delivery. |
| Revoke commits before authorization | Authorization returns `Revoked` with zero authorization/event writes and the dispatch path performs zero Adapter begin-delivery and zero native send. |
| Snapshot expires after authorization commits | That exact authorization remains valid. There is no authorization TTL or second Context state check; Attempt lease/fencing and Adapter at-most-once still apply. |
| Snapshot is already expired but remains Issued when revoke commits | Matching authenticated Founder owner may commit the revoke governance fact; no consumption becomes authorized. |
| Exact authorization replay | Returns the original authorization receipt and performs no new Authority or Adapter action. |
| Same idempotency key or dispatch tuple with different semantic input | Fails as a conflict with zero writes and zero send. |
| Concurrent storage conflict before either commit is known | Fails closed or retries only the Authority transaction; it must not call Adapter until one durable authorization receipt is known. |

An authorization receipt is evidence for one dispatch, not a bearer token for
arbitrary callers. The governed Adapter entry must verify the exact snapshot,
attempt, dispatch and input digest binding before `begin_delivery`. Missing,
malformed, conflicting or unverifiable authorization means zero send.
After authorization commits, the exact dispatch path must not call the generic
Context resolve path again and use a later expiry or revoke to overturn that
grant. It verifies the durable authorization receipt and the existing Attempt
lease/fence and Adapter delivery facts instead.

## Frozen invariants

1. Context Authority is the only writer of snapshot governance state,
   `state_revision`, revoke events and dispatch-consumption authorizations.
2. Snapshot bytes, descriptor, snapshot ID, snapshot revision and compiled
   content digest are byte-for-byte unchanged by revoke and authorization.
3. `state_revision` is independent of snapshot revision. Only a governance
   state transition increments it; authorization records only the revision it
   observed.
4. Founder identity is derived from the authenticated local session. A client
   cannot supply or override `authenticated_principal_id`, principal kind or
   Authority reference.
5. Revoke is allowed only for the authenticated Founder owner whose principal
   ID exactly matches the snapshot's immutable `owner_principal_id` and who has
   the Local API revoke permission. An Issued snapshot remains revocable after
   expiry; expiry bars consumption rather than governance recording.
6. Revoke and authorization are idempotent by principal, idempotency key and a
   canonical semantic request digest. Exact replay returns the original
   result; key reuse with different semantics fails with zero writes.
7. Authorization is bound to exactly one canonical snapshot ID, attempt ID,
   dispatch ID and verified input digest. No field may be inferred from native
   Provider output or mutable runner memory.
8. A durable authorization receipt is required before Adapter begin-delivery.
   A resolve result, log entry, in-memory flag or recovery material is not an
   authorization substitute. Authorization has no separate TTL: it checks
   expiry at commit, after which the exact grant is bounded by existing Attempt
   lease/fencing and Adapter at-most-once delivery.
9. Revoke is prospective. It does not mutate Task, Run, Step or Attempt, cancel
   native work, undo an external effect or invalidate an authorization that
   committed first.
10. After revoke, every new resolve, confirmation, activation and dispatch
    authorization fails closed. No fallback to static or stale Context
    material is allowed for a `ctx:` binding.
11. Recovery and reconciliation may read previously bound immutable material
    through the recovery-purpose seam only. That seam cannot mint an
    authorization, enter a new dispatch, retry, create an Attempt or authorize
    a dispatch resend. The read seam itself performs no external action.
12. Receipt, authorization, revoke event, recovery finding and Harness
    observation never complete a Task. Task status remains Task Authority
    owned.
13. Capability-profile status and revocation remain outside R-9A.
14. New revoke commits use a lowercase ASCII reason slug and lowercase ASCII
    namespaced evidence/proof references under Scheme C, not content payloads.
    They remain in the local
    Context Authority audit store for the same lifecycle as their event and
    are never echoed as raw references by Local API.
15. CLI, TUI and gateway use one shared Rust semantic request-digest oracle.
    Presentation text is not digest input and cannot change revoke semantics.

## Contract shapes

The names below freeze semantic fields, ownership and validation. Protobuf tag
numbers and generated bindings are introduced only in the contract-first
R-9A.2 revision.

### `RevokeContextSnapshotCommand`

| Field | Requirement |
|---|---|
| command metadata | Command ID, idempotency key, canonical request digest, correlation ID and optional causation ID. Authenticated principal ID/kind and Authority reference are server-derived. |
| `snapshot_id` | Canonical `ctx:<sha256>` only. |
| `expected_state_revision` | Non-zero CAS value for the current governance state. |
| `reason_code` | One lowercase ASCII slug matching `^[a-z0-9]+(?:-[a-z0-9]+)*$`, 1 to 128 bytes. |
| `evidence_refs` | One to 16 lowercase ASCII namespaced references matching `^[a-z0-9]+(?:-[a-z0-9]+)*(?::[a-z0-9]+(?:-[a-z0-9]+)*)+$`, each 1 to 512 bytes and no more than 4,096 bytes in aggregate. |
| `confirmation_proof_ref` | One lowercase ASCII namespaced reference matching the same reference expression, 1 to 512 bytes, binding the Founder owner to this exact revoke request. |

Every new-commit reason/evidence/proof value must satisfy Scheme C exactly.
The Authority rejects rather than normalizes a value that violates these
rules. These fields carry identifiers only; raw or
encoded Context bytes, Provider output, prompts, credentials and native
evidence payloads are forbidden. They are stored transactionally in the local
Context Authority audit database and retained whenever the corresponding
Authority event is retained. They are not copied to a new service, general
log, telemetry sink or public projection.

Historical records created before Scheme C remain replayable only when the
authenticated principal, idempotency key and full semantic request digest all
match the durable record. Exact replay returns the original receipt with
`replayed=true` and zero writes. Changed semantics under the same key return
idempotency conflict before new-commit Scheme C validation, also with zero
writes. Historical compatibility never normalizes or rewrites stored facts.

The result contains `replayed`, snapshot ID, unchanged snapshot revision and
content digest, previous/resulting governance state, previous/resulting
`state_revision`, request digest, event ID and commit time. It never returns
compiled Context bytes, the full descriptor, raw reason/evidence values or the
confirmation proof reference through Local API.

### `AuthorizeDispatchContextConsumptionCommand`

This is an internal Rust Authority command, not a Local API or UI command.

| Field | Requirement |
|---|---|
| command metadata | GovernanceKernel principal, command ID, idempotency key, canonical request digest, correlation ID and causation ID. |
| `snapshot_id` | Exact Task-bound canonical Context snapshot. |
| `expected_state_revision` | Non-zero state revision observed from the current governed preparation/activation path. |
| `attempt_id` | Exact Collaboration Attempt. |
| `dispatch_id` | Exact immutable dispatch identity. |
| `input_digest_sha256` | Existing verified SHA-256 identity of the immutable dispatch input consumed by Adapter; R-9A does not invent a new RunPlan digest algorithm. |
| `expected_scope_ref` | Exact immutable scope already bound by the Task/Context path. |

The result contains `replayed`, an immutable `authorization_id`, the complete
authorization tuple, observed state revision, snapshot revision, request
digest, event ID and commit time. Adapter validation must receive the complete
receipt; passing only `authorization_id` is insufficient. Authorization checks
snapshot expiry inside its commit transaction and adds no independent TTL.
Later expiry or revoke does not invalidate the exact committed receipt.

### `RecoveryContextMaterialRequest`

This internal GovernanceKernel read seam is separate in type and entry point
from dispatch authorization. It contains snapshot ID, attempt ID, dispatch ID,
input digest, a bounded recovery evidence reference and the fixed purpose
`recovery_or_reconciliation`. It may return already-bound immutable bytes and
descriptor facts after revocation or expiry, together with the observed state
and integrity result.

The recovery result contains no authorization ID, no send permission and no
conversion into a dispatch-consumption receipt. It is admissible only when the
caller proves an existing historical attempt/dispatch binding. Missing or
conflicting lineage fails closed.

R-9A.1 adds only this recovery-purpose type and the Context Authority-owned
read entry point. It does not connect production runners, Collaboration,
Adapter reconciliation or any dispatch path to the entry point. Production
dispatch/recovery wiring and proof that it cannot resend belong exclusively to
R-9A.3.

### Events and errors

Context Authority emits immutable `ContextSnapshotRevoked` and
`DispatchContextConsumptionAuthorized` events in its own monotonic audit
sequence. Events state committed facts and are never instructions to send,
cancel or mutate another Authority.

Typed failures must distinguish invalid input, unauthenticated, permission
denied, owner mismatch, not found, expired for consumption, revoked, scope
mismatch, integrity failure, state revision conflict, idempotency conflict,
authorization tuple conflict and storage unavailable. `Expired` is not a
revoke failure while the governance state is still Issued. Failure responses
contain no partial success receipt. Only an exact idempotent replay carries the
original committed event.

## Public Local API and surfaces

R-9A.2 adds a typed Context revoke Local API operation and permission
`local.context.revoke`. Authorization policy must bind it to the Context
Authority and the authenticated Founder-owner principal kind. The gateway
derives the principal from the local session, performs final permission
preflight, and delegates the state decision to Context Authority.

CLI and TUI expose the same revoke capability through the shared Rust client
attachment and one Rust semantic request-digest oracle. The digest is a full
64-hex SHA-256 over the contract-frozen semantic request, including the
server-bound Founder owner, snapshot ID, expected state revision, reason,
evidence references and confirmation proof reference; command ID,
idempotency key, correlation/causation metadata and presentation text are not
semantic digest inputs. The contract revision must freeze the canonical byte
encoding and fixtures before either surface is implemented; neither surface
may implement a second canonicalizer.

Interactive CLI confirms the computed full digest; non-interactive CLI must
supply the complete digest, not a prefix or yes/no bypass. TUI uses a modal to
confirm that same full digest. The gateway derives the authenticated Founder
owner, recomputes the full digest with the shared oracle and rejects missing,
malformed, truncated or mismatching confirmation before calling Context
Authority. Confirmation wording and layout are presentation details, not part
of the frozen contract. Neither surface can author an Authority receipt,
state, principal or event. Desktop is not an R-9A acceptance surface.

## Minimum development order

### R-9A.1 — Authority and store

- add the Founder-owner principal and revoke command/result/event;
- add independent `state_revision` with a forward-compatible migration for
  existing rows;
- add immutable dispatch-consumption authorization, idempotency and audit
  records;
- serialize revoke and authorization in the same Context Authority write
  boundary;
- add only the distinct recovery-purpose type and Context Authority read entry
  point without any send grant or production runner/Adapter wiring.

### R-9A.2 — Local API, permission and CLI/TUI

- revise contracts and their manifest/digests before cross-surface code;
- add `local.context.revoke` and bind it to Context Authority/Founder owner;
- route the typed operation through Local API and shared ClientAttachment;
- freeze and reuse one semantic request-digest oracle and gateway verifier;
- expose interactive/full-digest CLI and modal TUI confirmation with the exact
  same digest binding;
- project only a sanitized revoke receipt, not Context bytes or raw evidence.

### R-9A.3 — Dispatch/recovery seam and real E2E

- require the durable complete authorization receipt before Adapter
  begin-delivery;
- preserve Adapter at-most-once behavior when authorization won the race;
- prove revoke-first produces zero authorization writes and zero send;
- wire the recovery-purpose read entry to the production governed recovery and
  reconciliation path without granting dispatch or resend;
- prove recovery/reconciliation can inspect historical immutable material but
  cannot enter a new dispatch or resend;
- close the real daemon path with durable restart evidence and an independent
  external-side-effect witness.

No later sub-slice may be used to conceal an incomplete earlier Gate.

## Implementation checkpoint

R-9A.1 is implemented and locally verified. The checkpoint includes the
Founder-owner revoke API, independent governance `state_revision`, the
forward-only legacy/pre-R-9A store migration, durable revoke and exact-dispatch
authorization receipts, one Context Authority `IMMEDIATE` write boundary,
authorization-first/revoke-first ordering, and a recovery-purpose read type
that cannot authorize sending. It deliberately adds no Local API operation,
CLI/TUI surface, production Adapter dispatch wiring or production recovery
caller; those remain R-9A.2 and R-9A.3 work.

Verification evidence at this checkpoint:

- nine focused `r9a_` tests pass, including restart replay, expired revoke,
  both deterministic dual-connection linearization orders, tuple tamper,
  bounded private audit input and pre-R-9A migration preservation;
- all 23 cognition-runtime library tests pass;
- the complete local CI passes contract/boundary/TypeScript checks, the Rust
  workspace gates and all three Python worker suites;
- SQL transaction and architecture-contract reviews report GO with no open
  R-9A.1 P0/P1 finding.

This was the R-9A.1 checkpoint only. Complete R-9A closure is recorded after
the later R-9A.2 and R-9A.3 checkpoints below.

R-9A.2a is also implemented as the contract-first checkpoint. Draft.18 adds the
typed `ExecuteContextMutation`/`revoke_context_snapshot` operation,
`local.context.revoke`, the independently projected `context_state_revision`,
the Context Authority/Founder command rule and a sanitized revoke receipt. The
machine-readable semantic profile freezes exact UTF-8 bytes with no
normalization, `u64` little-endian length framing, evidence count and request
order, and the full lower-case 64-hex SHA-256 confirmation. Fixed valid and
fail-closed digest fixtures are manifest-controlled, and one shared Rust oracle
is now consumed by Context Authority commit/recovery verification. Rust,
TypeScript and Python bindings are generated from the same Proto. The compiled
Local API method remains deliberately fail-closed with an unavailable response
until R-9A.2b replaces that transitional endpoint with authenticated session,
permission and Context Authority routing.

R-9A.2a verification evidence:

- the contract candidate validates 244 manifest artifacts and 184 fixtures;
- all 44 Rust, TypeScript and Python generated files are clean against the
  draft.18 Proto and manifest digest;
- 12 domain-contract tests, nine focused R-9A cognition tests, 10 client-kernel
  tests and 45 Local API tests pass;
- the complete local CI passes after the profile-digest integration baselines
  were advanced with the contract profile;
- independent architecture, build and test reviews report GO with no remaining
  R-9A.2a P0/P1 finding.

R-9A.2b is implemented as the authenticated Local API and daemon-routing
checkpoint. The gateway derives the Founder principal only from the trusted
OS-peer-bound session, enforces `local.context.revoke` and the exact frozen
`ContextAuthority.Founder` profile constraint, validates bounded command
metadata, requires a canonical lower-case SHA-256 value, and recomputes the
full semantic digest before constructing a private verified command. The
daemon independently requires an explicit reviewed `context_kind: "Founder"`
binding; permissions never select or elevate an Authority principal kind.
The production adapter uses the same Context Authority handle as preparation
and existing Context consumers, maps typed Authority failures without erasing
owner/CAS/revoke/idempotency semantics, and emits only a sanitized receipt
whose snapshot and request digests are checked before return.

R-9A.2b verification evidence:

- all 50 Local API tests pass, including five focused Context gateway tests for
  real IPC/session authentication, permission and client binding, fixed digest
  verification, bounded metadata, all typed public failure mappings, zero
  pre-Authority calls and private-field non-disclosure;
- one Windows component test crosses the real production seam from IPC session
  through `CommandGatewayApplication`, its privately constructed verified
  command and `ContextMutationPortAdapter` into the real SQLCipher Context
  Authority; first commit and exact replay preserve the complete receipt while
  durable event/receipt/idempotency counts do not grow on replay;
- 13 focused daemon Context tests and an exhaustive Authority/resolver failure
  mapping test pass; explicit Founder binding, profile drift and absent binding
  remain fail closed;
- independent architecture, build and test reviews report GO with no remaining
  R-9A.2b P0/P1 finding, and the complete local CI passes.

R-9A.2b by itself did not add CLI/TUI revoke interaction,
dispatch-consumption authorization, production recovery wiring, a daemon
restart witness or an Adapter side-effect witness. The first item is closed by
R-9A.2c below; the remaining dispatch/recovery witnesses are still R-9A.3 work
and must not be inferred from same-process exact replay evidence.

R-9A.2c is implemented as the shared CLI/TUI confirmation checkpoint. One
`client-operations` prepare path derives the Founder identifier only from the
accepted kernel session, delegates canonicalization to the frozen domain
oracle and returns an opaque prepared request with safe display getters. The
execute path consumes that request, rechecks the exact session ID, principal,
permission and complete lower-case digest before generating metadata or
calling transport, then validates the sanitized Authority receipt. It never
changes the caller's idempotency key and does not retry automatically.

The CLI supports a zero-mutation preview, exact-digest non-interactive
execution and a terminal-only prompt that requires typing the complete digest;
JSON or redirected execution never prompts. The prompt removes only its CR/LF
line ending, so padded confirmation is rejected instead of normalized. The TUI
has no headless Context mutation subcommand: its form creates independent,
ordered evidence entries, preserves each entry's exact bytes, and redacts the
reason, evidence and proof values while they are edited. It stages an opaque
pending commit through the already attached interactive client, displays only
snapshot, CAS revision, evidence count and the complete digest, drops the
pending commit on `Esc`, and consumes it at most once on `Enter`. Both
work-preparation surfaces expose `contextStateRevision`, the governed CAS
input.

R-9A.2c verification evidence:

- shared client-operation tests cover the independent fixed canonical bytes
  and digest, CLI/TUI semantic-command byte equality, permission denial,
  malformed and mismatching confirmation with zero send, session/principal
  binding, exact request construction, typed errors and strict receipt
  validation;
- TUI component tests drive form to modal through one injected attached-client
  seam and prove `Esc` sends zero commits, `Enter` consumes exactly one commit,
  the full digest is visible, and private inputs are not rendered. A Windows
  real-process CLI test crosses OS-authenticated IPC, the daemon gateway,
  production Context adapter and SQLCipher Authority for first commit and
  byte-equivalent replay while scanning stdout and stderr for private Context,
  owner, reason, evidence and proof sentinels;
- the real-process test exposed an existing Windows stack-overflow risk in the
  large TUI async command dispatcher. The command future is now explicitly
  heap-pinned at both console and quiet entry points. Existing real-process TUI
  command regressions pass without increasing or overriding the process stack;
  this is not presented as a Context-modal subprocess E2E;
- this evidence proves user-surface confirmation and durable Context revoke,
  not dispatch linearization, restart recovery or Adapter side-effect safety.

### R-9A Gate 1-12 closure checkpoint

R-9A.3 is implemented and all twelve gates below are locally verified. Gates
1-6 retain the immutable migration, Founder ownership, deterministic dual
connection linearization, tuple integrity and shared CLI/TUI digest evidence.
Gate 7 proves a successful prospective revoke leaves the complete existing
Adapter receipt bytes and Task/Run/Step/Attempt facts unchanged. Gate 8 proves
historical recovery uses immutable material without authorization or resend.
Gate 9 covers both authorization-first and revoke-first daemon restart orders
with a durable independent external-side-effect witness rather than process
memory or Recording driver logs. Gate 10 proves those paths create or advance
no Founder Verdict. Gate 11 freezes Scheme C for new commits and exact
principal/key/full-digest historical replay with zero writes; changed
semantics conflict before new validation. Gate 12 proves production recovery
and reconciliation cannot become a send path.

This closure changes no Proto field, tag or RPC, no Context Authority SQL
schema or migration, and no semantic digest algorithm, canonical field order
or fixed vector. It does not claim any R-9B/R-9C capability.

## Acceptance Gates

1. **Immutable migration:** existing snapshots acquire a valid initial
   `state_revision` without changing snapshot IDs, revisions, descriptors,
   bytes or digests; rollback/restore behavior is documented.
2. **Revoke authority:** authenticated matching Founder owner commits exactly
   one revoke; unauthenticated, unauthorized, cross-owner, stale CAS and
   malformed requests produce zero state/event writes. An expired Issued
   snapshot is revocable by that same owner and still remains unusable for
   consumption.
3. **Idempotency:** exact revoke and authorization replay return the original
   receipt across restart; changed semantics under the same key or tuple fail
   with zero writes.
4. **Linearization:** deterministic concurrency tests force both commit orders.
   Authorization-first permits only that dispatch; revoke-first produces zero
   authorization/event writes, zero Adapter begin-delivery and zero send.
   Expiry or revoke after authorization does not invalidate the exact grant,
   introduce a second Context check or bypass Attempt lease/fencing and Adapter
   at-most-once behavior.
5. **Integrity binding:** tampering with snapshot, attempt, dispatch, input
   digest, scope, authorization receipt or state revision fails before Adapter
   with zero send.
6. **Surface contract:** contract/profile validation proves the Local API
   permission and server-derived principal; CLI and TUI use the same client
   attachment and cannot self-author an owner or GovernanceKernel command. The
   shared canonical fixtures prove interactive CLI, non-interactive full
   digest, TUI modal and gateway recomputation bind identical semantic bytes;
   truncated or mismatching digests fail before an Authority call.
7. **Prospective semantics:** revocation leaves Task/Run/Step/Attempt and
   existing Adapter receipts unchanged; subsequent new resolve, confirm,
   activation and authorization requests fail closed.
8. **Recovery separation:** after revoke, historical recovery material remains
   integrity-verifiable for the exact attempt/dispatch, while send, retry, new
   Attempt and dispatch authorization counters remain zero.
9. **Real daemon evidence:** on Windows, controlled process/restart witnesses
   prove authorization-first at-most-once send and revoke-first zero send using
   durable Authority facts and an independent test-only side-effect counter,
   not in-memory logs.
10. **No false completion:** all success and recovery cases assert that no
    Context event or Adapter observation directly completes Task or advances a
    Founder verdict.
11. **Bounded private audit input:** boundary tests cover empty, over-limit,
    padded and control-character reason/evidence/proof values and reject raw
    or encoded Context/Provider payloads. New commits require the exact Scheme
    C lowercase slug/namespaced-reference syntax. Exact historical replay is
    bound to principal, key and full digest with zero writes; changed semantics
    conflict before new validation. Local API, projection, logs and telemetry
    expose none of the raw references.
12. **Recovery staging:** R-9A.1 exposes only the typed Authority read entry and
    has no production caller. R-9A.3 separately proves production wiring can
    reconcile an existing dispatch while the native dispatch-send counter and
    new-authorization counter remain zero.

## Non-goals and forbidden expansion

- R-9B governed-state streaming, cursors, replay or reset/refetch UI;
- R-9C redacted Harness content streaming, terminal content or Artifact return;
- capability-profile revoke or any Harness Registry state transition;
- Provider routing, new Provider capabilities, Memory/RAG or Desktop work;
- mutation, replacement, deletion or reissue of revoked snapshot content;
- automatic Task/Run/Step/Attempt mutation, cancellation, retry, compensation,
  new Attempt or reversal of an external side effect;
- client, Adapter, Harness or test-only SQL writes to Context Authority state;
- use of recovery material, resolve results or logs as dispatch authorization;
- an independent dispatch-authorization TTL or a post-authorization general
  Context state check that can overturn the exact committed grant;
- an external evidence, audit, retention or confirmation service;
- a new canonical RunPlan digest or reinterpretation of the existing template
  digest as dynamic instance content identity.

## Frozen implementation defaults

1. An Issued snapshot remains formally revocable after expiry by its matching
   authenticated Founder owner. Expiry blocks consumption; revoke records a
   terminal governance fact and does not authorize any work.
2. Exact dispatch authorization has no independent TTL. Context Authority
   checks expiry when authorization commits. After commit, later expiry or
   revoke cannot overturn that exact grant; existing Attempt lease/fencing and
   Adapter at-most-once delivery remain mandatory.
3. New reason, evidence and proof inputs use the bounded Scheme C rules in this
   document. The Context Authority local audit database retains them for the
   corresponding event lifecycle. Exact historical replay remains bound to
   principal, idempotency key and full digest without rewriting the record.
   Local API, projections and general telemetry never echo the raw references,
   and R-9A adds no external system.
4. CLI and TUI confirm one shared semantic request digest: interactive CLI or
   non-interactive complete digest, TUI modal, and mandatory gateway full-digest
   verification before the Authority call. Wording is not frozen.

There is no remaining Founder decision inside the frozen R-9A scope. A new
Founder decision is required before changing these defaults, allowing a
non-owner revoke, making revoke retroactive, adding an authorization TTL,
exposing raw audit references, moving retention to an external system, or
expanding into R-9B/R-9C or capability revocation.

The R-9B-only expansion decision was subsequently granted and is recorded in
`phase-2-75-r9b-governed-state-dual-stream-contract-20260904.md`. That decision
does not authorize R-9C, capability revocation or any change to R-9A defaults.

## Exit condition

R-9A is complete only when all three sub-slices and all applicable Gates have
durable evidence. R-9A does not claim R-9B/R-9C streaming, capability revoke,
real Provider coverage, terminal Artifact closure or complete product release.
