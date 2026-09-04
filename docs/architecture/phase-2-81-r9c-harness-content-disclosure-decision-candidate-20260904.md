# R-9C user-visible Harness content disclosure decision candidate

- Date: 2026-09-04
- Status: `recommended_pending_founder`
- Decision owner: Founder
- Scope: R-9C disclosure contract only
- Parent decisions:
  - `phase-2-56-context-revoke-and-consumption-linearization.md`
  - `phase-2-75-r9b-governed-state-dual-stream-contract-20260904.md`
  - `phase-2-80-r9b-real-process-c5-evidence-20260904.md`

This document is a decision candidate, not a frozen contract and not an
implementation authorization. It records repository facts, compares the real
options, and proposes one complete decision package for Founder review.

## 1. Decision required

R-9A and R-9B intentionally did not decide what native Harness content may be
shown to a user. R-9C must now define a resumable, redacted, provider-neutral
content stream for CLI and TUI while preserving the frozen rule:

> A live Harness observation is not Task completion, an Artifact, independent
> verification, or a Founder verdict.

The decision is architectural because it fixes trust boundaries, ownership,
information disclosure, recovery semantics, and the contract every Provider
adapter and client surface must obey.

## 2. Repository facts

The following are current implementation facts rather than recommendations.

1. `HarnessObservation` contains structured ACK, lifecycle, approval, usage,
   checkpoint, artifact-return and diagnostic metadata. It has no portable
   user-visible text payload.
2. `HarnessAdapterService.SubscribeObservations` is an adapter-facing stream.
   Its messages include native digests and raw evidence references, and its
   request has no Local API session permission or Local Read Model
   epoch/reset contract. It is not a safe client API.
3. Adapter Edge durably stores each native event, its digest, a normalized
   observation and source ordering. It also stores terminal-output candidates.
4. A terminal-output candidate is explicitly not an Artifact, Claim,
   verification result or completion fact. The return collector must admit it
   through Artifact Authority before it becomes a governed result.
5. The existing capture budget is 16 MiB for complete attempt output and a
   64 KiB preview for an incomplete oversized candidate (`QR-04`). Those
   internal limits do not themselves authorize disclosure.
6. Local Read Model, Local API, Client Kernel and `client-operations` already
   implement the reusable baseline/watch, permission, epoch/sequence,
   heartbeat, retention-gap, `ResetRequired`, bounded recovery and safe DTO
   patterns used by Task and Approval.
7. CLI and TUI share one Rust Client Kernel and Local API. They differ only in
   presentation and must not implement separate disclosure decisions.
8. Codex already receives an explicit `agentMessage` delta channel but only
   accumulates it for terminal return. Command output, file-change output and
   reasoning deltas are separate native categories. Other Provider adapters
   require their own mapping and admission proof.

## 3. Options considered

| Candidate | Why choose it | Cost | What it gives up | Exit path |
|---|---|---|---|---|
| A. Structured events only | Lowest disclosure risk and mostly maps to existing lifecycle/usage metadata | Still requires a safe Local API projection, permission and replay contract | No readable streaming answer; cannot honestly complete the product's R-9C goal | Remains the safe degradation mode inside B |
| B. Structured events plus governed user-visible text | Delivers useful natural-language streaming while preserving a provider-neutral governance boundary | New normalized candidate contract, deterministic disclosure profile, projection schema, Local API RPC, client driver and per-Provider proofs | No raw terminal fidelity, hidden reasoning, arbitrary tool output or Provider-native UI | Text can be disabled by profile and safely degrade to A without changing Authority facts |
| C. Raw terminal/native stream | Useful only for terminal debugging or PTY fidelity | High secret/PII/control-sequence risk, Provider coupling, binary framing and much larger retention/audit surface | Reliable redaction and stable cross-Provider semantics | Must be a later, separate, default-off diagnostic decision; never a silent upgrade from B |

### Recommendation

Choose **B: structured events plus governed user-visible text**.

Candidate A is a useful fallback but is not a sufficient product interaction.
Candidate C conflicts with the already frozen requirement for a redacted
user-visible stream and would harden unstable Provider protocols into a global
client architecture.

## 4. Proposed frozen decision package

Every item in this section remains `recommended_pending_founder` until the
Founder explicitly confirms `R9C-D01` through `R9C-D12`.

### R9C-D01 - product shape

R-9C uses candidate B. CLI and TUI receive one shared provider-neutral content
model containing governed structured activity and governed assistant text.
There is no client-facing raw-terminal mode in R-9C.

### R9C-D02 - ownership and trust

- Founder is the disclosure decision owner. The versioned profile only encodes
  the Founder-frozen rule; it is not an Authority or autonomous policy owner.
- Adapter Edge remains the durable source-of-record for native event facts,
  native order, raw evidence and normalized source candidates. It is not a
  business Authority.
- Adapter Edge also owns an exact safe-record ledger, streaming assembly/
  redaction state, owner-side safe baseline/current-message snapshot and an
  acknowledged projection outbox. Safe bytes and their profile binding are
  persisted there before they are eligible for disclosure.
- A deterministic disclosure projector runs inside the existing `agentosd`
  process. It is the sole producer of safe content records and is not a new
  external service or business Authority.
- Local Read Model is the sole writer of the derived user-visible projection.
- Artifact Authority remains the sole owner of admitted final output and
  Artifact lineage.
- Task, Collaboration, Policy, Sego Verification, Founder Verdict, Context and
  Memory ownership do not move.
- CLI, TUI and future Desktop are consumers only. They do not inspect native
  events and do not perform a second, surface-specific disclosure decision.

Native event/candidate commit and safe-record/outbox commit are two recoverable
Adapter Edge transactions. The second transaction atomically commits message
assembly state, redaction cursor, safe records, profile/credential-set
commitment and projection outbox rows. A crash between them reprocesses the durable
candidate; a crash after the second commit replays the exact safe record and
does not re-run redaction.

### R9C-D03 - normalized source contract

Provider adapters may emit a `UserVisibleContentCandidate` only when the
native protocol explicitly identifies content as a user-facing assistant
message or as an allowlisted structured activity.

The candidate does not self-report Task, Provider or model identity. It is
paired with one durable Harness content-signal observation and is accepted
only after Adapter Edge verifies all of the following trusted source tuple:

```text
durable Delivered receipt ID/digest
  + closed Context-consumption proof branch
  + Adapter/capability profile ID and immutable dispatch route-binding digest
  + Run/Step/Attempt/Dispatch/Fence lineage resolved through trusted stores
  + native event identity/digest/sequence
  + normalized message identity/revision/operation/digests
```

Only a durable `Delivered` receipt may produce a content signal. The projector
resolves Task lineage from the existing dispatch-to-Task binding; Task ID is
not accepted from the Provider candidate. Provider/model display aliases are
derived from the immutable route binding and catalog snapshot, never from
candidate text.

The Context-consumption proof is a closed branch:

- `NOT_CONTEXT_BOUND` must be the existing trusted dispatch classifier result;
- `AUTHORIZED_CONTEXT` must carry and verify the exact committed R-9A
  dispatch-consumption authorization ID/digest;
- malformed `ctx-`/`ctx:` references, a missing branch or a branch mismatch
  fail closed.

Both branches still require the durable `Delivered` receipt. The
`AUTHORIZED_CONTEXT` branch is non-retrospective: later Context revoke does not
invalidate a dispatch whose exact authorization already committed.

During trusted workflow/profile resolution, before Collaboration commits the
dispatch intent, the Governance Kernel constructs a new immutable
`DispatchRouteBinding` from the selected Provider bootstrap profile and catalog
snapshot. The binding is carried through the resolved `SingleHarnessWorkConfig`
and included by Collaboration in the original `DispatchEnvelope`. The Adapter
material resolver validates that exact binding against its selected material/
profile; it does not enrich an envelope after Adapter Edge preparation.
Adapter Edge persists the already-bound envelope with the dispatch record
before native send. Material/profile validation may run after that idempotent
preparation but must finish before `begin_delivery`; validation failure leaves
only the unchanged prepared record and causes no native effect. The binding
contains Provider profile ID, selected harness and Provider model IDs,
catalog-snapshot digest (or an explicit no-catalog
sentinel), capability-profile ID and a canonical route-binding digest. Restart
and config change read the stored binding and never recompute historical
identity from the current bootstrap file.

The pre-disclosure candidate carries `bytes text_utf8` and a closed operation
enum: `APPEND`, `REPLACE` or `FINALIZE` (`UNSPECIFIED` is invalid).

- Revision starts at 1. Every later event carries the exact previous revision
  and previous raw cumulative SHA-256 digest.
- `APPEND` carries one delta; its cumulative digest covers prior raw message
  bytes followed by the delta.
- `REPLACE` carries one complete replacement snapshot; its cumulative digest
  covers that complete snapshot.
- `FINALIZE` carries no text and repeats the prior cumulative digest.
- Delta/snapshot digest, cumulative digest and the source tuple use one
  canonical length-prefixed encoding fixed by contract fixtures.
- An exact same-revision replay is a no-op. The same identity/revision with a
  different digest is quarantined. A revision gap, invalid predecessor,
  second finalize or update after finalize fails closed.

Transport chunk boundaries are not product semantics. The stable content-event
ID is the SHA-256 of the complete immutable source tuple, so identical native
or message IDs from different dispatch routes cannot collide.

R-9C consumes only the already committed closed Context-proof branch. It never
authorizes, begins or sends a dispatch.

A content candidate is never an Artifact, completion fact, verification fact,
Memory fact or authorization decision.

The candidate Proto is inside the Adapter trust boundary and may contain bytes
that will be blocked or redacted. It is never a Local API or client DTO.

### R9C-D04 - visible and forbidden categories

The initial allowlist is:

- assistant text from an explicitly user-visible native channel;
- frozen lifecycle/activity/status codes, without arbitrary Provider reason
  strings;
- bounded usage counters;
- `APPROVAL_REQUIRED` as a closed status code; the Approval stream remains the
  source of request identity and details;
- for the one finalized message only, a safe relation to an already authorized
  final-message Artifact view;
- redacted, blocked, truncated and content-domain status markers.

The initial hard denylist is:

- hidden reasoning or chain-of-thought, including Provider reasoning deltas;
- system/developer prompts and Provider request payloads;
- direct Context or Memory/RAG source fields, queries, embeddings, proofs or
  source refs;
- tool arguments, raw tool results, command stdout/stderr, ANSI/control bytes,
  file contents and workspace paths;
- raw native events, raw evidence references and native routing/session/
  execution identifiers;
- credentials, tokens, private keys, environment values and secret-store
  material;
- any unknown category.

The denylist prohibits those raw fields and source categories from being
directly projected. It does not claim that semantic inference can identify and
remove every fact an assistant restates in natural language. Owner-authorized
assistant text may contain the owner's ordinary personal, Context-derived or
task data. R-9C does not claim generic, infallible PII or semantic-DLP removal.
That data remains `local-user-data`, is restricted to the owning Task scope,
and is not eligible for sharing or export through this contract.

### R9C-D05 - redaction and text-safety semantics

Disclosure is allowlist-first and fail-closed:

1. structurally remove every field not present in the safe content contract;
2. reject forbidden source categories before reading their payload as display
   text;
3. validate `text_utf8`; invalid UTF-8 produces one `INVALID_TEXT` blocked
   marker and no text bytes;
4. normalize CRLF and CR to LF, map TAB to four ASCII spaces, map Unicode line/
   paragraph separators to LF, and replace each C0 control other than LF, DEL,
   C1 control and each bidi-control scalar in the exact set U+061C, U+200E,
   U+200F, U+202A-U+202E and U+2066-U+2069 with U+FFFD while setting a
   `CONTROL_REDACTED` flag; no ANSI parser or terminal control interpretation
   is allowed;
5. redact exact locally managed credential variants with a deterministic
   streaming multi-pattern matcher; treat heuristic secret patterns only as
   defence in depth, not as proof of `QH-06`;
6. replace a rejected item with a closed safe reason code; never echo the
   matched fragment;
7. commit the safe record to the Adapter Edge safe ledger before its outbox can
   disclose it to Local Read Model.

For `ApiKeyEnvironment`, text disclosure supports at most 32 non-empty managed
credential values, each at most 1,024 printable ASCII bytes. The finite matcher
set is exactly:

1. the raw ASCII bytes;
2. canonical JSON content escaping, with only `"` and `\` prefixed by `\`, no
   optional `\/` and no `\u` form;
3. canonical percent encoding, where RFC 3986 unreserved bytes
   `ALPHA / DIGIT / - / . / _ / ~` remain literal and every other byte is `%`
   plus two uppercase hexadecimal digits;
4. RFC 4648 standard Base64 padded and unpadded;
5. RFC 4648 URL-safe Base64 padded and unpadded.

Selective/lowercase percent encodings, PEM, arbitrary Unicode escapes and
other reversible encodings are outside this finite guarantee; heuristics may
block them but cannot close a security Gate. The longest guaranteed encoded
pattern is 3,072 bytes. The streaming automaton
withholds only the current suffix that is a proper prefix of a managed pattern,
bounded by 3,071 bytes, across candidate/frame boundaries. `REPLACE` resets the
message matcher from its replacement snapshot; `FINALIZE` safely flushes the
remaining non-secret suffix.

If an environment credential exceeds these bounds, text disclosure for that
Attempt degrades to structured-only mode; Provider execution is not rejected.
The daemon passes the matcher an ephemeral value set already resolved for
Harness launch. Values never enter Proto, logs or a database. Adapter Edge
derives a domain-separated HMAC-SHA-256 key from its existing store key and
persists only an HMAC commitment over the canonical, length-prefixed variant
set. This is not an unkeyed secret digest and is not exposed outside Adapter
Edge.

For `HarnessAccount`, the daemon does not possess the delegated credential.
The testable R-9C guarantee is therefore limited to: no daemon-managed
credential variant and no bytes from a forbidden native source category cross
the safe-record boundary. Provider admission must separately prove that its
public assistant channel is structurally distinct from authentication,
environment, tool and terminal channels. R-9C does not claim to detect an
unknown delegated secret invented or restated inside arbitrary natural
language.

One Attempt keeps the credential values captured at dispatch until message
finalization; rotation affects new Attempts. After a projector restart, pending
text is processed only if the current ephemeral set matches the persisted HMAC
commitment. A mismatch or unavailable set emits `REDACTION_INPUT_UNAVAILABLE` and
degrades the remaining Attempt to structured-only mode. Already committed safe
records remain replayable byte-for-byte.

The raw source remains governed Adapter Edge evidence. Every safe record binds
the disclosure profile ID, version and digest. A profile change creates a new
projection epoch and forces `ResetRequired`. The new baseline excludes all old
profile text, contains one `PROFILE_CHANGED_HISTORY_UNAVAILABLE` tombstone and
may include a separately authorized final-Artifact relation. Historical safe
bytes are neither reinterpreted nor copied into the new epoch.

### R9C-D06 - authorization

Add the independent surface-neutral permission:

```text
local.harness.content.read
```

The Local API resolves Task ownership and Attempt lineage from trusted state.
Clients cannot self-declare owner, scope, Provider, fence or source identity.
Task, Evidence or Approval read permission cannot substitute for this
permission.

The gateway revalidates the session grant and owning Task scope before each
baseline page, frame and heartbeat, after acquiring the send reservation and
immediately before the transport send. At most one frame may be in flight. A
session expiry/invalidation committed before that revalidation sends zero later
frames; a frame whose final check already succeeded may still arrive. The
bounded post-change exposure is therefore one serialized frame. On denial the
gateway discards unsent content, returns typed `PermissionDenied`, and requires
a new authorized baseline/client generation; the old cursor cannot be resumed
on that connection.

R-9C v1 Gate exercises real session expiry/invalidation through the production
session clock/lifecycle; a test-only permission toggle is insufficient. R-9C
adds no new runtime permission-revocation writer. If a future product
requires zero-byte revocation linearized against transport send, that requires
a separate Authority/transport decision rather than a claim this read stream
cannot enforce. Permission and content-worker failure terminates only the
content domain; Task and Approval streams continue independently.

### R9C-D07 - projection and recovery

R-9C is a third independent read domain, not a third member of the R-9B
Task/Approval composite reducer.

- It has its own epoch, monotonically increasing projection sequence,
  retention floor and cursor.
- Baseline is read at one fixed projection position; watch starts after that
  exact position.
- Source ingestion is at-least-once and projection is idempotent by stable
  content-event identity and digest.
- Adapter Edge retains an exact safe-record ledger, owner-side safe baseline/
  current-message snapshot, record digest, profile/credential-set commitment,
  assembly/redaction checkpoint and acknowledged outbox. Local Read Model
  rebuilds only from that owner ledger/snapshot, never by scanning raw
  candidates or re-running redaction. Its own baseline snapshot is a derived
  copy, not the owner recovery source.
- Exact replay within the retention floor returns the exact same safe bytes and
  metadata.
- A gap, expired cursor, epoch change or unavailable baseline produces typed
  `ResetRequired`. The client discards an incomplete assembly and rebaselines.
- Heartbeats, duplicate replay and stale worker generations do not advance the
  committed content position.
- Integrity conflict is content-domain fatal. A blocked content category is an
  event-local safe marker and does not stop execution.
- Permission, content message, worker and stream failures cannot stop or
  rewrite Task or Approval state. This does not promise isolation from loss of
  the shared process, database engine or filesystem.

Projection arrival order is a display order only. It is not a global causal
order across models, agents or Authority domains.

### R9C-D08 - bounded resource, accounting and retention

The architectural rule is that every frame, page, Attempt and retained history
is finite, profile-driven and observable; no component silently drops content.

Initial `v0.1` quality-profile values are recommended as follows:

- one source candidate and one safe text payload: at most 64 KiB after the
  relevant stage's UTF-8 validation; larger native text is split before
  candidate commit into maximal prefixes of at most 65,536 bytes that never
  split a UTF-8 scalar;
- one serialized safe Local API frame: at most 80 KiB;
- one Attempt: at most 16 MiB of committed safe text payload and 16,384 safe
  records; record slot 16,384 is reserved for `LIMIT_REACHED`;
- one Task across all Attempts: at most 64 MiB of committed safe text payload
  and 65,536 safe records; the final slot is likewise reserved;
- one baseline page: at most 256 whole records and 1 MiB of safe text payload;
- safe-record ledger and Local Read Model content retain replayable text for a
  minimum of 30 days after the trusted Task Authority terminal commit time;
- Founder pin applies to the canonical Artifact, not to all transient stream
  chunks.

Byte accounting uses safe normalized/redacted text payload bytes before Proto
encoding. Every persisted `APPEND` or `REPLACE` payload counts in full;
metadata-only records count only against the record limit. Whichever byte or
record limit is reached first wins. The reserved `LIMIT_REACHED` marker has a
stable ID derived from the source tuple, profile and limit kind; it consumes the
reserved record slot and zero text bytes. A final fitting prefix may be emitted
only after deterministic UTF-8 splitting, followed by that marker. Later text
candidates create no safe rows or outbox messages; existing native evidence
retention and one bounded aggregate omission fact remain separate.

Pagination includes only whole records. The record limit is applied first and
the byte limit second. `next_page_cursor` is the sequence of the last returned
record at the fixed snapshot position, with `has_more=true`; a page cannot be
empty while an eligible record exists because one record is smaller than the
page byte bound.

The 16 MiB/64 KiB values intentionally copy the initial numeric values of
`QR-04` but are governed by an independent disclosure profile; `QR-04` does not
implicitly authorize or account for safe projection storage.

Normalization may expand a candidate (for example TAB to four bytes or one
control scalar to the three-byte U+FFFD encoding). After normalization and
redaction, the projector deterministically splits the safe sequence again into
maximal valid UTF-8 prefixes of at most 65,536 bytes. Parts carry stable
zero-based `part_index` and fixed `part_count`, and their IDs add that index to
the immutable source tuple. Attempt/Task byte and record checks run on these
safe parts in order. If the remaining byte budget cannot hold a whole scalar,
no partial scalar is emitted and the reserved limit marker follows.

Frame-history compaction may occur earlier when the count/byte floor is
reached, but only after Adapter Edge atomically persists an owner-side safe
baseline/current-message snapshot that represents all compacted effects. It
then advances the owner safe-ledger floor/deletes older safe records in that
same transaction and emits one typed compaction record for Local Read Model;
consumers receive `ResetRequired` and rebaseline from the owner snapshot's
derived copy. Loss of Local Read Model remains rebuildable from Adapter Edge.

Thirty days is a minimum retention, not an exact wall-clock deletion promise.
An `agentosd` internal compactor (not a service) uses an injected/testable clock
and may compact on its first run at or after `terminal_committed_at +
2,592,000s`. It first commits the Adapter Edge floor/tombstone and deletion in
one transaction, then projects that decision to Local Read Model through the
acknowledged outbox. A tombstone retains Task/Attempt IDs, final epoch/
sequence, final safe-content digest, profile digest, terminal commit time,
compaction time and reason, but no text. It prevents rebuild from resurrecting
expired content from raw evidence. Non-terminal Tasks are bounded by the
Attempt/Task caps rather than an unbounded clock exemption.

Execution is not reported as completed or failed merely because disclosure
reached a limit or was compacted.

These values are versioned quality settings rather than hard-coded ownership
rules. Changing them requires a profile revision and fitness evidence, not an
Authority redesign.

### R9C-D09 - terminal content and Artifact relationship

- `message finalize` means only that a user-visible message stopped changing.
- a Harness terminal event means only that the native Dispatch stream ended;
- a terminal-output candidate is provisional and may be truncated or rejected;
- an Artifact becomes canonical only after Artifact Authority validates
  lineage/digest/sensitivity/retention and seals it;
- Sego verification and Founder verdict remain later, independent facts;
- only the frozen Task Authority transition may complete a Task.

CLI/TUI label live content as provisional. R-9C v1 relates only the one final
finalized assistant message for an Attempt to the existing
`final_message_artifact_id`; arbitrary live messages receive no Artifact
relation. The return collector must prove the same Attempt/Dispatch and exact
raw cumulative digest before creating the relation. The internal raw digest
and public safe digest remain distinct.

The Local API includes the authorized Artifact ID/digest only when the same
principal also holds `local.evidence.read` for the Task. Otherwise it emits an
`ARTIFACT_AVAILABLE_REDACTED` status without identity. If live text and the
Artifact differ because of redaction, truncation or normalization, the
Artifact is canonical and the UI says that the provisional display differs;
it never compares the raw and safe digests as though they should match.

### R9C-D10 - multi-model identity and presentation

Persistent identity and idempotency use immutable Provider bootstrap profile
ID, route-binding digest, capability-profile ID, catalog-snapshot digest,
Attempt/Dispatch/Fence and native event digest. A display alias is derived from
that binding and is never used as a durable key. Every public record exposes
only the safe Provider family/model alias and collaboration role. It never
exposes a native session or routing identifier.

CLI emits source-labelled records. TUI renders separate model/agent lanes by
default. Records may be visually interleaved by observed projection time, but
the UI must not blend them into one unattributed answer or claim cross-model
causal ordering.

### R9C-D11 - architecture footprint

The minimal implementation:

- does **not** add a new Authority or independent database;
- does add a versioned disclosure profile;
- extends `NativeHarnessDriver`/`DriverEvent` and Harness Proto with a content
  signal and normalized pre-disclosure content candidate because real resumable
  text is part of R-9C, not a later product substitute;
- extends Harness `DispatchEnvelope` and Adapter dispatch rows with the
  Governance-Kernel-created immutable `DispatchRouteBinding`;
- extends Adapter Edge schema with candidate/message-redaction state, exact
  safe-record ledger, owner baseline/current-message snapshot, acknowledged
  projection outbox, floor/tombstone, HMAC commitment and retention metadata;
- composes the deterministic disclosure projector and retention worker inside
  existing `agentosd`;
- extends Local Read Model schema with safe content view/baseline snapshot,
  frame history, inbox, floor, epoch/profile and compaction metadata;
- extends the existing `LocalReadModelService`, reader, gateway and notifier
  with Local API baseline/watch messages and RPC; it does not add a network
  service;
- updates the Local API authorization profile with the independent permission;
- does add one shared Client Kernel / `client-operations` content driver;
- maps Codex's explicit assistant-message channel first, then connects CLI and
  TUI in that order to the same driver;
- adds fixed contract fixtures, generated Rust/Python/TypeScript bindings and
  manifest pins.

Two existing databases receive schema migrations: Adapter Edge and Local Read
Model. No third database is introduced. The v1 Artifact Proto is unchanged
because D09 deliberately limits the relation to the existing final-message
handoff; a future arbitrary live-message relation would require a separate
Artifact contract decision.

Runtime-mutating, per-record disclosure policy is outside R-9C v1. If it is
later required, its writer and revocation semantics need a separate Authority
decision; it must not be smuggled into Local Read Model or a UI preference.

### R9C-D12 - completion gates

R-9C closes only when all of the following pass:

1. **Contract Gate** - closed enums/oneofs, profile schema, fixtures, Buf/
   breaking checks, manifest pins and Rust/Python/TypeScript generated bindings.
2. **Disclosure Gate** - every allow/deny branch, every specified managed-secret
   encoding split at every boundary, invalid UTF-8, the exact control-scalar
   set, oversize input and unknown kinds prove zero forbidden source bytes in
   safe-record Proto, Local API Proto, Local Read Model and client output
   buffers. Pre-disclosure candidate/raw-evidence Proto is intentionally inside
   the Adapter trust boundary and may contain the canary.
3. **Source Integrity Gate** - durable Delivered receipt; both the trusted
   `NOT_CONTEXT_BOUND` and exact R-9A `AUTHORIZED_CONTEXT` branches; malformed
   Context classification; trusted Task lineage; persisted route/profile/
   fence/native digests; operation/revision rules; idempotency; cross-model
   collision; replay conflict and quarantine tests. It also proves R-9C never
   issues a new authorize/begin/send and never makes Context revoke
   retrospective.
4. **Projection Gate** - restart recovery, duplicate replay, retention floor,
   profile reset with the exact tombstone-only old-history baseline, bounded
   pagination and exact safe-byte replay from the safe ledger.
5. **Authorization Gate** - independent permission denial plus production
   session expiry/invalidation (not a fake dynamic revocation writer),
   Task/Attempt scope isolation, revalidation-before-send, the one-frame upper
   bound and mandatory new baseline after reauthorization while Task and
   Approval streams remain live.
6. **Client Driver Gate** - bounded channel/reconnect/shutdown, generation
   fencing, no silent loss and no cross-domain cursor or completion inference.
7. **CLI Gate** - scriptable source-labelled streaming and stable NDJSON.
8. **TUI Gate** - the same semantic records, model lanes, provisional labels,
   reset/recovery state and clean process shutdown.
9. **Real Windows C5 Gate** - the production native Codex event must travel
   through Adapter candidate, safe ledger/outbox, projector, Local Read Model,
   Local API, shared client and real CLI/TUI; direct safe-projection seeding is
   forbidden. The Gate covers same-root D1/D2 process restart, retention gap,
   one-domain disconnect, permission loss, secret/control canaries, read-only
   durable-store oracles and no residual processes.
10. **Crash/compaction Gate** - forced process death in three distinct durable
    windows: after raw candidate commit but before safe-ledger commit; after
    safe-ledger/outbox commit but before Local Read Model commit; and after
    Local Read Model commit but before Adapter Edge ACK. It also kills during
    profile/credential-set change and concurrently with retention/watch/
    rebuild. READ_ONLY/query_only oracles prove exact source/safe bytes,
    inbox/outbox/ACK identities and counts, exact floor, no re-redaction, no
    resurrection, no loss and no duplicate disclosure.
11. **Non-completion/Authority Gate** - message finalize, terminal, limit,
    reset, replay and restart cannot complete a Task. Observation-only windows
    leave Task, Policy, Artifact, Verification, Verdict, Context and Memory
    Authority row counts/digests unchanged; normal return-collector writes are
    accepted only with their separate owner lineage.
12. **Optional Provider mapping Gate** - R-9C core closes with the currently
    admitted Codex Harness. DeepSeek, Kimi and GLM remain governed by their
    independent Provider admission decisions. Only after one is admitted and
    declares the governed-text capability may it run this additional mapping
    Gate; an unsupported mapping degrades to structured-only mode and R-9C
    never promotes Provider admission status.
13. **Local CI Gate** - focused suites and the complete local CI pass; GitHub
    Actions is supplementary while the repository quota is unavailable.

## 5. Implementation order after Founder confirmation

1. **R9C.0** - freeze this decision and the disclosure/quality profiles.
2. **R9C.1** - add Proto/profile/schema contracts, generated bindings and
   contract tests.
3. **R9C.2** - add the Adapter Edge candidate/outbox and Codex mapping, then the
   deterministic disclosure projector and Local Read Model.
4. **R9C.3** - add Local API, Client Kernel and shared client operation.
5. **R9C.4** - connect and verify CLI, then TUI.
6. **R9C.5** - close the real Windows C5 and local-CI evidence.
7. **R9C.6** - after each independent Provider admission, add its governed-text
   mapping proof one Provider at a time; R-9C does not perform that admission.

A final-only Artifact view or structured-only status stream may be useful
incremental evidence, but neither is accepted as completion of R-9C. The
product requirement is real, governed natural-language streaming.

## 6. Cost and future pressure

Choosing B spends additional engineering effort in every Provider adapter and
adds storage, redaction, replay and client-state complexity. Exact managed-
credential matching can delay a suffix that is currently a possible secret
prefix, with a 3,071-byte worst-case bound for the initial profile.
It also deliberately refuses terminal fidelity and hidden reasoning, so some
debugging information remains available only through governed evidence or a
future diagnostic contract.

In return, frontier models and Harness protocols can change without changing
the client-facing trust model. A new Provider must map into the same narrow
candidate contract and pass the same admission Gate. That is the architectural
value: the stable boundary is ownership and disclosure semantics, not one
current Provider SDK or streaming event format.

## 7. Founder action

Implementation remains `NO-GO` until the Founder either:

- confirms `R9C-D01` through `R9C-D12` as one package; or
- names the exact decision IDs and replacement text to revise.

After confirmation, this document must be changed from
`recommended_pending_founder` to a Founder-frozen status with an explicit
conversation authority reference before production contracts are edited.
