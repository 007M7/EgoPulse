# R-9C implementation readiness and traceability plan

- Date: 2026-09-04
- Status: `founder_frozen_r9c0_complete_r9c1_authorized`
- Decision owner: Founder
- Decision authority: `conversation:2026-09-04:founder-froze-r9c-d01-d12-and-phase-2-82-section-7`
- Integration DRI: Codex main window
- Frozen decision contract: `phase-2-81-r9c-harness-content-disclosure-decision-candidate-20260904.md`
- Planning baseline: `ec00da617cc78acb7b2afcd91cfec31cf7cd0772`

This plan was non-authorizing when first published. The explicit Founder
authority recorded below now freezes `R9C-D01` through `R9C-D12`, accepts the
section 7 migration/rollback contract and authorizes ordered implementation.
The plan remains the execution boundary: implementation may not reopen the
architecture or invent files, owners or Gates while coding.

## 1. Current readiness verdict

**R9C.0 is complete. R9C.1 is authorized after isolated writer setup.**

The decision package completed architecture, build and test review with no
known P0/P1 defect. The Founder then explicitly accepted the full decision and
migration/rollback packages. The acceptance is recorded in phase 2-81 and in
section 11 below; it is not inferred from a generic continuation instruction.

Before the first production edit, all of the following must be true:

1. **Satisfied:** the Founder explicitly confirmed `R9C-D01` through
   `R9C-D12` as one package;
2. **Satisfied:** phase 2-81 records the conversation authority reference and
   Founder-frozen status;
3. **Satisfied:** the Founder explicitly confirmed the migration activation,
   pre-R-9C legacy-row and rollback contract in section 7 before either
   SQLCipher schema is edited;
4. the next monotonic contract draft is allocated from the then-current
   `contracts/manifest.json`; `draft.20` is only the current expected value and
   must not be assumed if another contract revision lands first;
5. separate Git worktrees/branches are created for each writing window, with
   one owner per file; the three helper panes currently share one worktree and
   therefore remain read-only until that split exists;
6. the exact test names exist before a filtered test command is accepted as
   evidence. A successful command that runs zero tests is a failure.

## 2. Repository facts that constrain implementation

The plan is based on the following observed repository facts at the planning
baseline, not on proposed abstractions:

- `HarnessObservation` carries structured ACK, lifecycle, approval, usage,
  checkpoint, artifact-return and diagnostic payloads, but no portable safe
  content payload.
- `NativeHarnessDriver::next_event` returns `DriverEvent`; Codex already sees
  the explicit `item/agentMessage/delta` and completed `agentMessage` channels,
  but currently accumulates them only for the terminal-output candidate.
- Adapter Edge is in `crates/harness-adapter/src/edge.rs`. Its SQLCipher schema
  is an embedded ordered migration set currently ending at `SCHEMA_V3`.
- Local Read Model is in `crates/local-read-model`. Its SQLCipher schema is an
  independent embedded ordered migration set currently ending at `SCHEMA_V3`.
- `apps/agentosd/src/projections.rs` owns the in-process projection pump. The
  daemon is a deployment host, not a new fact owner.
- `LocalReadModelService`, its reader/gateway/notifier and the existing
  Task/Approval streams are in `crates/local-api`; there is no Harness-content
  RPC today.
- CLI and TUI already consume shared Rust operations through
  `crates/client-operations` and `crates/client-kernel`. R-9C must add a third
  independent content driver, not fold content into the R-9B Task/Approval
  reducer.
- Codex is the only admitted production Harness. DSH, Kimi and OpenCode/GLM
  remain independent provider-admission candidates. R-9C core cannot promote
  them.
- Contract generation is manifest-bound and regenerates TypeScript, Rust and
  Python trees. `scripts/contract-codegen.ps1` also pins the source manifest
  digest, so changing Proto without updating that pin and the generated
  manifest must fail.
- GitHub Actions capacity is currently supplementary. Local focused tests and
  complete local CI are the release evidence; CD is not run at every coding
  packet.

## 3. Frozen dependency direction to preserve

```text
Founder-frozen disclosure + authorization + quality profiles
                         |
                         v
Harness Proto: route binding + normalized pre-disclosure candidate
                         |
                         v
Provider adapter native mapping (Codex first)
                         |
                         v
Adapter Edge native facts + safe ledger + acknowledged outbox
                         |
                         v
agentosd in-process deterministic projector / compactor
                         |
                         v
Local Read Model safe projection (third independent read domain)
                         |
                         v
Local API baseline/watch + independent permission
                         |
                         v
shared Client Kernel / client-operations content driver
                         |
                 +-------+-------+
                 |               |
                CLI             TUI
```

No UI, TypeScript Harness or Python Worker gains a database handle or an
Authority write. Raw native events and pre-disclosure candidates stop inside
the Adapter trust boundary. Only safe records can enter Local Read Model and
the clients.

## 4. Decision-to-implementation traceability

| Decision | Preserved owner/boundary | Primary implementation locus | Closure evidence |
|---|---|---|---|
| D01 product shape | shared provider-neutral structured activity plus governed assistant text; no raw terminal | Harness/Local API DTOs, shared client driver, CLI/TUI renderers | identical safe record identity and position reach CLI/TUI; rendering may differ |
| D02 ownership | Founder owns disclosure rule; Adapter Edge owns durable source/safe ledger; Local Read Model owns only derived view | Adapter Edge transaction, `agentosd` projector, Local Read Model inbox | crash-window oracle and unchanged Authority-store digests |
| D03 source contract | trusted Delivered receipt, closed Context branch and immutable route binding; candidate is not an Authority fact | Harness Proto, dispatch material resolution, `DriverEvent`, Adapter Edge | tuple tamper, revision, replay, cross-route collision and no-authorize/no-send tests |
| D04 allow/deny | allowlist first; forbidden raw sources never become display text | closed enums/oneofs and Provider mapping | fixed positive/negative fixtures; unknown kind fails closed |
| D05 text safety | deterministic normalization/redaction before safe-ledger eligibility | disclosure profile plus Rust projector/redactor state | independent fixed vectors, split-boundary canaries and restart commitment tests |
| D06 authorization | independent `local.harness.content.read`; Task scope resolved from trusted state | authorization profile, session/gateway send reservation | production expiry/invalidation, scope denial and at-most-one-frame exposure |
| D07 recovery | third cursor/epoch/floor; safe ledger is rebuild source | Adapter outbox, Local Read Model content module, client tracker | exact replay, gap/reset, stale generation and owner-ledger rebuild |
| D08 bounds/retention | profile-driven finite records/pages/history; no silent loss | disclosure profile, Adapter/LRM counters and `agentosd` compactor | exact-boundary, limit marker, pagination, 30-day clock and no-resurrection tests |
| D09 Artifact relation | finalize, native terminal, Artifact, verification, verdict and Task completion remain distinct | return relation join plus authorized Local API projection | exact lineage/digest, evidence-read gating and non-completion store oracle |
| D10 multi-model | route identity is durable; alias is presentation only | route binding, content IDs and surface lane model | same native ID on distinct routes stays distinct; alias changes do not alter keys |
| D11 footprint | no new Authority, service or third database | two additive SQLCipher migrations and existing process/crates | repository boundary checks and dependency review |
| D12 completion | no partial or renderer-only closure | contract, component, C4, C5 and local-CI suites | all 13 phase 2-81 Gates with non-zero exact tests and durable evidence |

## 5. Planned file impact

Names under **new** are implementation candidates. They may be adjusted within
the same owner/module only if the frozen semantics and the one-writer map do
not change.

### 5.1 Contract and generated boundary

Modify:

- `contracts/proto/egopulse/harness/v1/harness.proto`
- `contracts/proto/egopulse/localapi/v1/local_api.proto`
- `contracts/profiles/authorization/v1/v01-default.json`
- `contracts/authorization-capability-profile.schema.json` only if its closed
  shape/count constraints require an additive update
- `contracts/profiles/client-kernel/v1/v01-default.json` and
  `contracts/client-kernel-profile.schema.json` to distinguish the new
  operation-record content stream from the existing Task/Approval
  complete-snapshot streams; the existing complete-snapshot invariant must not
  be weakened globally
- `crates/domain-contracts/src/profiles.rs` for the exact disclosure,
  authorization, client-profile and Local API digest bindings
- `contracts/scripts/validate-candidate.js`
- `contracts/manifest.json`
- `contracts/IMPLEMENTATION-SSOT.json`
- `contracts/IMPLEMENTATION-SSOT.md`
- `scripts/verify-v01-contract-import.mjs`
- `scripts/contract-codegen.ps1` source-manifest digest pin
- `config/agentos-config.example.json`
- `contracts/fixtures/localapi/v1/valid-open-desktop-session.json`; this is a
  shared session fixture update, not Desktop feature implementation

Add:

- `contracts/harness-content-disclosure-profile.schema.json`
- `contracts/profiles/harness-content-disclosure/v1/v01-default.json`
- Harness fixtures for valid candidate, forbidden category, source-binding
  drift, revision/digest drift and exact replay
- Local API fixtures for baseline/watch, unauthorized read and retention reset
- persistence fixtures for safe-outbox replay after consumer commit
- `crates/domain-contracts/tests/harness_content_r9c.rs` for contract/profile
  fixed vectors

Regenerate; never hand-edit as contract truth:

- `crates/domain-contracts/src/generated/egopulse.harness.v1.rs`
- `crates/domain-contracts/src/generated/egopulse.localapi.v1.rs`
- corresponding files under `packages/generated-client/src/generated/`
- corresponding files under `workers/contract-bindings/src/`
- `generated/contract-bindings-manifest.json`

The write sequence is: edit contract truth, refresh the contract manifest,
update the manifest digest pin, run `pnpm run generate:contracts`, then check
the generated trees. Generated outputs and their source contracts are one
atomic review packet.

### 5.2 Adapter Edge and Provider mapping

Modify:

- `crates/harness-adapter/src/runtime.rs`
- `crates/harness-adapter/src/edge.rs`
- `crates/harness-adapter/src/lib.rs`
- `crates/harness-adapter/Cargo.toml`, root `Cargo.toml` and `Cargo.lock` only
  if a new workspace-pinned cryptographic/encoding dependency is required
- `crates/codex-adapter/src/protocol.rs`
- `crates/codex-adapter/src/lib.rs` only if exports change
- `crates/codex-adapter/src/material.rs` only if the typed material seam must
  carry inputs into the Governance-Kernel-owned route-binding constructor;
  Provider code must not become the identity owner
- `crates/codex-adapter/src/fake.rs` and existing Provider-neutral/real-server
  tests whose `DriverEvent` construction must remain exhaustive
- `crates/local-ide-control/src/collaboration_control/ingestion.rs` only to
  keep its Harness payload handling closed and non-authoritative
- `crates/local-ide-control/src/collaboration_control/mod.rs`, which contains
  the production `DispatchEnvelope` constructor, plus the existing
  `harness_dispatch.rs` / `single_harness_workflow.rs` tests needed to prove
  the Governance-Kernel-owned route binding is inserted before Adapter send
- `crates/local-ide-control/tests/collaboration_control_g4_03.rs` for the exact
  committed-envelope, non-completion and no-post-prepare-mutation proofs
- `crates/dsh-adapter/src/lib.rs`, `crates/kimi-adapter/src/lib.rs` and
  `crates/opencode-adapter/src/lib.rs` only for exhaustive compilation and
  explicit structured-only degradation; this is not content admission

Candidate additions:

- `crates/harness-adapter/src/disclosure.rs` for deterministic, profile-bound
  normalization/redaction and assembly state used by the in-process projector
- `crates/harness-adapter/tests/harness_content_disclosure_r9c.rs`
- `crates/codex-adapter/tests/harness_content_r9c.rs`

The Adapter migration should prefer additive tables, including a
dispatch-route-binding table keyed by `dispatch_id`, over rewriting historic
dispatch rows. A pre-R-9C dispatch without a persisted route binding is not
backfilled from current configuration and is ineligible for text disclosure.

The binding injection point is fixed before implementation: trusted
`ConfiguredSingleHarnessWorkflow` derives the binding from the selected
profile/catalog and carries it in `SingleHarnessWorkConfig`; Collaboration's
`build_dispatch_envelope` includes it in the original envelope before the
dispatch intent is committed. The Adapter material resolver validates the
binding after idempotent Edge preparation but before `begin_delivery`/native
send, and never enriches a previously persisted envelope. A validation failure
leaves only that unchanged prepared record. This costs additional typed data
through the workflow seam and updates to G4-03 fixtures, but preserves one
envelope fingerprint, exact replay and a single trusted identity instead of
introducing a post-persistence identity mutation.

### 5.3 Projector, retention and Local Read Model

Modify:

- `apps/agentosd/src/projections.rs`
- `apps/agentosd/src/bootstrap.rs`
- `apps/agentosd/src/context_material.rs` for the trusted dispatch-material
  and closed Context-proof seam
- `apps/agentosd/src/return_collector.rs` for the narrowly authorized final
  finalized-message relation in D09; Artifact Proto remains unchanged
- `apps/agentosd/src/lib.rs`
- `apps/agentosd/tests/config_check.rs`
- `crates/local-read-model/src/lib.rs`
- relevant Cargo manifests only for dependencies actually used

Candidate additions:

- `apps/agentosd/src/harness_content.rs`
- `apps/agentosd/src/harness_content_retention.rs`
- `crates/local-read-model/src/harness_content.rs`
- `crates/local-read-model/tests/harness_content_read_model_r9c.rs`
- `apps/agentosd/tests/harness_content_r9c.rs`, which is only the in-process
  component/integration target; it is not real Windows C5 evidence

The retention worker is an internal daemon component with an injected clock,
not a new service. Local Read Model rebuild reads only Adapter safe
ledger/snapshot material; it must have no API capable of scanning raw native
candidate payloads. Content epoch, sequence, floor, reset and compaction
metadata are independent from the existing Task/Approval projection metadata;
a content reset must not clear or advance either existing domain.

### 5.4 Local API and shared client

Modify:

- `crates/local-api/src/read_model_reader.rs`
- `crates/local-api/src/read_gateway.rs`
- `crates/local-api/src/read_gateway_policy.rs`
- `crates/local-api/src/read_service.rs`
- `crates/local-api/src/read_tokens.rs` only if the independent content cursor
  requires the existing token envelope to recognize a new domain
- `crates/local-api/src/lib.rs`
- `crates/client-kernel/src/lib.rs`
- `crates/client-operations/src/lib.rs`

Candidate additions:

- `crates/client-operations/src/harness_content_driver.rs`
- `crates/local-api/tests/harness_content_gateway_r9c.rs`
- `crates/client-kernel/tests/harness_content_stream_r9c.rs`
- `crates/client-operations/tests/harness_content_session_r9c.rs`

The content driver owns only bounded client stream state. It cannot infer Task
completion, merge its cursor with Task/Approval, or reinterpret redaction.

### 5.5 CLI, TUI and conformance evidence

Modify:

- `apps/cli/src/main.rs`
- `apps/tui/src/lib.rs`
- `apps/tui/src/main.rs`
- `apps/agentosd/tests/c5_00_daemon_fixture.rs`
- `contracts/toolchain/fault-conformance/src/lib.rs`
- `contracts/toolchain/fault-conformance/src/main.rs` only if a CLI oracle
  route is needed
- `scripts/check-rust.ps1` so the separately rooted fault-conformance crate is
  executed by both local CI and the existing GitHub Rust job

Add:

- `apps/tui/src/harness_content.rs`
- `contracts/toolchain/fault-conformance/src/r9c_harness_content.rs`
- `contracts/toolchain/fault-conformance/tests/r9c_crash_recovery.rs`
- `scripts/check-r9c-test-inventory.ps1`, containing the exact non-zero test
  inventory and rejecting a missing/duplicate name before any Gate is credited
- `apps/cli/tests/harness_content_r9c.rs`
- `apps/tui/tests/harness_content_r9c.rs`

CLI must expose a stable source-labelled NDJSON mode in addition to human
text. TUI renders model/agent lanes and provisional labels from the same shared
records. Desktop is outside this work package.

## 6. Work packets, sole writers and merge order

The following allocation becomes active only after Founder freeze and after
isolated worktrees are created.

| Packet | Sole writer | Scope | Dependency | Merge condition |
|---|---|---|---|---|
| R9C.0 freeze record | main DRI | phase 2-81 status/authority reference, this plan status and section 7 migration/legacy rules | Founder confirmation | exact decision IDs and migration contract recorded |
| R9C.1 contract truth | main DRI | Proto, profiles, schemas, manifest/SSOT and generated bindings | R9C.0 | Contract Gate and non-zero fixed-vector tests |
| R9C.2A Adapter/Provider | build window | driver candidate, route binding, Adapter V4/safe ledger/outbox, Codex mapping | R9C.1 | source, disclosure and Adapter recovery tests |
| R9C.2B projector/LRM | main DRI | in-process projector/compactor and LRM V4 content domain | R9C.1; integrates R9C.2A types | projection, limits and rebuild tests |
| R9C.3 API/client | main DRI | RPC reader/gateway/session send checks, Client Kernel/operation | R9C.2B | authorization and client-driver Gates |
| R9C.4 surfaces | build window after 2A merge | CLI first, then TUI, both through shared operation | R9C.3 | CLI/TUI parity and shutdown tests |
| R9C.5 core closure | test window + main DRI | independent fixtures, component/C4/C5 tests, read-only oracle, integration, full local CI, evidence and push | contracts first; C5 after R9C.4 | clean tree, anti-false-green review and all exact Gates |
| R9C.6 Provider mapping | a separately authorized future writer | one Provider mapping proof after that Provider's own admission | R9C.5 core plus independent Provider admission | mapping Gate only; never changes admission status |

The architecture window remains read-only and can issue GO/NO-GO reviews. It
does not share file ownership with a writer. The test window may write only
test/conformance files assigned to it; it may not repair production code to
make its test pass.

Safe parallelism begins only after R9C.1 is merged. R9C.2A and the initial LRM
schema/test harness of R9C.2B may proceed in parallel because they live in
separate files/worktrees. API/client work waits for the Local API messages and
LRM access shape. TUI waits for the CLI/shared-driver semantic contract; it is
an order decision, not a capability reduction.

## 7. Founder-frozen migration and rollback contract

- Status: `founder_frozen`
- Risk acceptance owner: Founder

This architecture-significant contract was accepted explicitly and separately
from D01-D12. R9C.0 records that acceptance before schema work starts.

### 7.1 Forward migration

- Adapter Edge and Local Read Model each receive one new ordered, transactional
  migration; no third database is created.
- New tables/columns are additive. Historic native evidence is never rewritten
  into safe content and a missing historic route binding fails closed.
- New-dispatch code persists route binding before native send. Once the frozen
  profile is enabled, any failure to persist that binding prevents content
  eligibility and must not fall back to a recomputed current config.
- The two stores migrate independently but content projection is enabled only
  after both schema/profile digests pass startup validation.
- The D08 typed-limit correction advances the disclosure contract from
  `0.1.0` to `0.1.1`. Any pre-correction safe history remains immutable under
  its original profile digest; activation of `0.1.1` starts a new content
  epoch and never rewrites, re-redacts or backfills those bytes.
- At this correction point, `0.1.0` had no merged runtime writer and therefore
  produced zero product safe-history rows. It remains an auditable contract
  candidate in Git history rather than a loadable first-release profile. If
  contrary external write evidence is ever discovered, activation must stop
  until the exact legacy profile and vectors are restored for read-only replay.
- The additive Local API correction exposing the selected limit kind advances
  the implementation candidate from `draft.20` to `draft.21`. It changes no
  Authority, write owner, database migration or retrospective history rule.
- A coordinated pre-migration backup is required for the real Windows C5
  upgrade test.

### 7.2 Feature rollback

The supported runtime rollback is to disable governed text and degrade new
Attempts to structured-only mode while retaining native evidence, safe records
and tombstones. It must not delete rows, reinterpret bytes with an older
profile, or alter Task execution.

### 7.3 Binary rollback

The current store implementations bind metadata to a schema digest. Therefore
an old binary is not presumed able to open a store migrated by a newer binary.
Automatic down-migration is forbidden.

- Before any release migration, take and verify a coordinated backup.
- If startup migration fails before post-migration product writes, restore the
  verified backup and old binary as one operation.
- If post-migration writes exist, use the new binary's structured-only mode or
  a forward repair; do not silently restore an older database and lose facts.
- C5 must exercise both the no-write backup restore path and the post-write
  forward-disable path before release.

Profile rollback is a new profile revision and epoch reset. Old safe bytes are
not re-redacted or copied into the new epoch.

## 8. Acceptance and anti-false-green matrix

### 8.1 Contract Gate

Required checks:

```text
node contracts/scripts/validate-candidate.js
pnpm run check:contracts
pnpm run check:v01-contract-import
pnpm run check:contract-codegen
cargo test -p egopulse-domain-contracts --locked --test harness_content_r9c -- --test-threads=1
```

Fixtures use independent literal expected bytes/digests. They cannot call the
production canonicalizer/redactor to manufacture their expected values.

### 8.2 Component and integration Gates

Required focused suites, after their dedicated test targets exist:

```text
cargo test -p egopulse-harness-adapter --locked --test harness_content_disclosure_r9c -- --test-threads=1
cargo test -p egopulse-codex-adapter --locked --test harness_content_r9c -- --test-threads=1
cargo test -p egopulse-local-read-model --locked --test harness_content_read_model_r9c -- --test-threads=1
cargo test -p egopulse-local-api --locked --test harness_content_gateway_r9c -- --test-threads=1
cargo test -p egopulse-client-kernel --locked --test harness_content_stream_r9c -- --test-threads=1
cargo test -p egopulse-client-operations --locked --test harness_content_session_r9c -- --test-threads=1
cargo test -p egopulse-agentosd --locked --test harness_content_r9c -- --test-threads=1
cargo test -p egopulse-cli --locked --test harness_content_r9c -- --test-threads=1
cargo test -p egopulse-tui --locked --test harness_content_r9c -- --test-threads=1
```

Before any command above is credited,
`scripts/check-r9c-test-inventory.ps1` runs each target with `-- --list`,
requires every frozen exact test name exactly once, and requires each target's
expected count to equal its non-zero inventory count. The script then invokes
the separately rooted C4 suite. This executable guard, rather than prose or a
name filter, prevents a zero-test exit code from appearing green.

Minimum proofs include:

- exact replay/no-op versus same-revision digest conflict/quarantine;
- revision gap, second finalize and post-finalize update rejection;
- Delivered-only source binding and both closed Context-proof branches;
- no new authorize/begin/send and non-retrospective Context revoke;
- every allow/deny category, invalid UTF-8 and exact control-scalar set;
- every managed-secret representation split at every matcher boundary;
- 64 KiB/80 KiB/Attempt/Task/page exact-limit and plus-one cases;
- profile/credential mismatch degradation without re-redaction;
- permission denial, real session expiry/invalidation, one-frame maximum and
  mandatory new baseline;
- fixed baseline/watch pairing, duplicate/heartbeat, gap/reset, stale worker
  generation and owner-ledger rebuild;
- Artifact relation permission and all non-completion invariants;
- bounded channel, reconnect and clean shutdown;
- CLI NDJSON and TUI buffers contain no secret/control canary and preserve the
  same safe identity/position.

### 8.3 C4 crash and read-only oracle Gate

The fault-conformance oracle opens SQLCipher stores read-only/query-only,
checks metadata first, and never initializes, migrates or repairs a store. It
must inspect raw candidate, safe ledger, assembly checkpoint, outbox/ACK,
owner baseline/floor/tombstone and LRM inbox/content/frame/epoch records while
also proving Authority row counts/digests unchanged.

Required crash windows:

1. after raw candidate commit, before safe-ledger commit;
2. after safe-ledger/outbox commit, before Local Read Model commit;
3. after Local Read Model commit, before Adapter ACK;
4. during profile or credential-set change;
5. during retention/compaction concurrent with watch/rebuild.

The dedicated C4 target contains exactly these five frozen tests:

```text
r9c_crash_after_raw_candidate_before_safe_commit_recovers_once
r9c_crash_after_safe_outbox_before_read_model_commit_recovers_once
r9c_crash_after_read_model_commit_before_adapter_ack_replays_without_duplicate
r9c_crash_during_profile_or_credential_change_never_reredacts
r9c_crash_during_compaction_preserves_floor_and_prevents_resurrection
```

Each is run as an exact test, substituting the name above for `<exact_name>`:

```text
cargo test --manifest-path contracts/toolchain/fault-conformance/Cargo.toml --target-dir target --locked --test r9c_crash_recovery <exact_name> -- --exact --nocapture --test-threads=1
```

Expected C4 exact-test count: **5**. `scripts/check-rust.ps1` invokes the
inventory/C4 script explicitly because the fault-conformance crate is outside
the root workspace. Consequently both `pnpm run ci:local` and the existing
GitHub Rust job inherit the C4 Gate without moving that crate into the root
workspace.

No direct SQL seeding of a safe projection or handcrafted Reset is accepted as
end-to-end evidence.

### 8.4 Real Windows C5 Gate

The production Codex `agentMessage` must traverse:

```text
native event -> candidate -> safe ledger/outbox -> projector -> Local Read Model
             -> Local API -> shared client driver -> real CLI and real TUI
```

C5 uses different D1/D2 PIDs with the same managed root/IPC instance, hard
kill with bounded reap, a post-kill/pre-D2 read-only snapshot, finite deadlines
and a final no-residual-process check. It covers restart, retention gap,
one-domain disconnect, production session invalidation, secret/control
canaries and authorization-first Context revoke without redispatch.

The real test file remains `apps/agentosd/tests/c5_00_daemon_fixture.rs`.
Direct safe-projection seeding, renderer-only tests, log markers, historic R-9B
evidence and zero-test filters cannot close R-9C.

The C5 inventory contains exactly these six tests:

```text
r9c_real_windows_cli_tui_share_exact_safe_content_position
r9c_real_windows_restart_resumes_without_loss_duplicate_or_authority_write
r9c_real_windows_retention_gap_resets_content_only_and_rebaselines
r9c_real_windows_session_invalidation_stops_after_one_in_flight_frame
r9c_real_windows_secret_and_control_canaries_never_cross_safe_boundary
r9c_real_windows_authorization_first_context_revoke_is_nonretroactive_without_resend
```

Each is run as an exact test, substituting the name above for `<exact_name>`:

```text
cargo test -p egopulse-agentosd --locked --test c5_00_daemon_fixture <exact_name> -- --exact --nocapture --test-threads=1
```

Expected C5 exact-test count: **6**. The inventory guard proves those six names
exist exactly once; the authoritative Rust Gate may then run the complete C5
binary once in its established serial order instead of rerunning the same six
tests as a second suite.

The existing restart test is also the container for the two isolated migration
sub-scenarios required by section 7: before any post-migration product write it
must restore the verified coordinated backup and old binary as one operation;
after a post-migration product write it must reject old-binary restore and use
structured-only forward-disable without losing native evidence, safe records or
tombstones. These are required sub-scenarios, not two additional test names, so
the frozen C5 inventory remains exactly six.

### 8.5 Provider isolation and local CI

Codex closes R-9C core. DSH, Kimi and the existing OpenCode/GLM candidate each
receive a later, independent governed-text mapping proof only after their own
Provider admission permits it. There is no planned `glm-adapter` creation in
R-9C; the current GLM candidate lives behind `crates/opencode-adapter`.

The final local Gate follows the repository's existing authoritative order,
extended through `scripts/check-rust.ps1` with the R-9C inventory and explicit
C4 invocation:

```text
pnpm run ci:local
git diff --check
```

All Cargo commands added by R-9C use `--locked`. `pnpm run ci:local` already
performs contract/TypeScript checks, the locked Rust sequence, serial
`agentosd`/C5 tests and Python suites; a raw `cargo test --workspace` is not a
substitute for that order.

Run local CD/package assembly once for the integrated release candidate, not
after every packet. Given fresh passing local-CI evidence for the same HEAD,
the non-duplicating packaging command is:

```text
pnpm run cd:local -- -SkipCi
```

Tagging and public release remain a separate release authorization; R-9C does
not create a tag. A GitHub Actions result is informative while quota is
unavailable and does not replace the captured local evidence.

## 9. Risk register and stop conditions

| Risk | Detection | Required disposition |
|---|---|---|
| raw/provider text crosses safe boundary | canary scan at ledger, Proto, LRM, CLI and TUI | P0; stop merge and quarantine source |
| profile/candidate ambiguity | unknown enum/oneof or digest mismatch | fail closed; structured-only where D05 permits |
| historic identity recomputed from current config | dispatch lacks persisted route binding | no disclosure; never backfill by inference |
| Local API permission race overclaims zero-byte revocation | send-boundary expiry/invalidation test | enforce phase 2-81 one-frame bound; do not invent a revocation Authority |
| LRM rebuild re-runs redaction | raw candidate access observed | P0; rebuild only from owner safe ledger/snapshot |
| stream event completes or rewrites Task | Authority-store digest/count changes | P0; stop and restore ownership boundary |
| CLI/TUI implement separate tracker/redactor | duplicate surface state machine | reject; move semantics to shared Rust driver |
| R-9C promotes another Provider | admission/status/profile changed by mapping work | reject packet; Provider admission stays independent |
| contract generation appears green against stale manifest | source-manifest or generated digest drift | fail Contract Gate and regenerate from SSOT |
| helper windows write the shared worktree concurrently | overlapping uncommitted paths | stop, preserve changes, split worktrees before resuming |

## 10. Independent review record

The latest planning revision received three independent, read-only reviews
against baseline `ec00da617cc78acb7b2afcd91cfec31cf7cd0772`:

| Review | Result | Remaining P0 | Remaining P1 | Scope closed |
|---|---|---:|---:|---|
| architecture | GO | 0 | 0 | DoR, Authority ownership, dependency direction, legacy migration, rollback and Provider isolation |
| build | GO | 0 | 0 | real file impact, route-binding timing, D09/non-completion seams, generated artifacts and client-kernel profile locality |
| test | PASS | 0 | 0 | dedicated targets, non-zero inventory, exact C4/C5 evidence, fault-conformance CI reachability and local-CD ordering |

These are planning-level results only. All helper reviews were non-writing and
do not constitute Founder acceptance, production implementation evidence or a
Gate closure. No production contract or runtime file changed in this planning
unit.

## 11. Exit conditions and next action

This planning unit is complete when independent architecture, build and test
review find no unresolved P0/P1, repository checks pass, and the document is
committed/pushed without production changes.

The Founder action was recorded in conversation on 2026-09-04:

```text
确认冻结 R9C-D01～R9C-D12，并确认 phase-2-82 7 迁移与回滚合同
```

The phrase `phase-2-82 7` unambiguously identifies this document's section 7
and is normalized by the decision authority reference above. R9C.0 is complete.
R9C.1 is the next permitted production unit after isolated writer worktrees
exist; no helper window receives a production packet before that split.
