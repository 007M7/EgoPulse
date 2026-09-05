# R-9B real-process governed-state C5 evidence

- Date: 2026-09-04
- Status: Gate 9 closed / locally verified
- Parent contract: `phase-2-75-r9b-governed-state-dual-stream-contract-20260904.md`
- Driver contract: `phase-2-77-r9b2-governed-state-driver-contract-20260904.md`
- Surface contract: `phase-2-79-r9b2c-cli-tui-governed-state-surface-contract-20260904.md`
- Scope: real Windows daemon, IPC, CLI/TUI, isolation, retention reset and read-only Authority evidence

## Outcome

The R-9B C5 suite exercises the frozen governed-state design through an
independent child daemon, the real Windows IPC transport and the production
Rust client/session/controller paths. It proves that Task and Approval remain
two independently governed read streams carried by one shared
`ClientAttachment`. The suite neither creates a combined cursor nor compares
the two domain positions.

The implementation is evidence-only. It adds fixture modes and a strict
read-only conformance oracle, but no production Proto, RPC, database schema,
Authority writer, recovery hook, provider, Memory/RAG, R-9C or Desktop
behavior.

## C5-A: real CLI, TUI and same-root restart

`r9b_real_windows_dual_state_cli_tui_and_same_root_restart_are_consistent`
starts daemon D1 as a distinct process and observes the governed state through
the production controller. It then runs the real CLI command:

```text
egopulse state watch --updates 2 --json
```

The NDJSON initial record and independent Task/Approval live updates match the
safe TUI model. A real ConPTY TUI process opens the Governed State page and
shows both domains as Live together with the explicit warning that their
positions do not form an atomic snapshot or global cursor.

After bounded controller shutdown and process reap, daemon D2 starts with a
different PID over the same root and instance. Its safe Task and Approval facts
equal D1. Read-only Authority snapshots taken before and after both observation
runs and both process reaps remain exactly equal.

## C5-B: independent permission rejection

`r9b_read_permission_rejection_is_isolated_to_one_domain` runs symmetric real
process cases for Task-read denial and Approval-read denial. The denied domain
alone reaches Fatal with `permission_denied`, has no facts or position, and
cannot prevent the other domain from reaching Live with its complete facts.

Both cases use the production attachment and controller. Authority snapshots
before observation, after controller stop and after process reap remain exactly
equal.

## C5-C: one-domain disconnect and bounded recovery

`r9b_task_stream_single_disconnect_keeps_approval_live_and_recovers_bounded`
injects exactly one Task-stream unavailability at the read boundary. Task alone
becomes Stale, advances its own generation and consumes exactly one unit of its
own reconnect budget while preserving its last-good facts and position.

The Task rebaseline is held by a test-only deterministic barrier. During that
hold, Approval remains Live and advances from its own prior position through
the real projection pump. Releasing the barrier lets Task rebaseline and return
to Live within the bounded operation count. Approval generation, recovery
budget and facts remain independent throughout. No Task/Approval position is
compared or ordered against the other.

## C5-D: real retention gap and domain-local rebaseline

`r9b_retention_gap_resets_only_task_and_rebaselines_bounded` first reaches a
dual-Live baseline, records Task T0 and deterministically holds the old Task
live read. Approval then advances only against its own A0 baseline, and the
parent persists that A1 has been observed.

The parent sends a fixed `compact-at-current` request containing no Task or
Approval epoch or sequence. In the child, under one `LocalReadModel` lock, the
fixture reads and fixes the neutral current retention floor F, confirms the
position is still F and calls the real `compact_history(F.sequence)` exactly
once. The old and returned floor epochs are checked against F, and F plus the
old/current/returned floor facts are durably recorded. Local Read Model
compaction is the intended projection write; it is not an Authority write.

After the old Task read is released, the raw Task stream contains exactly one
ResetRequired frame with `PROJECTION_RETENTION_GAP`; the raw Approval stream
contains none. Task alone increments its generation, preserves T0 as its
last-good page and consumes no transport recovery budget. While the new Task
baseline is held, the ResetRequired page is stable. Releasing that barrier lets
Task return to Live beyond T0 and at or beyond F while Approval remains exactly
at its independently established A1 state.

The same read-only Authority oracle is sampled at six explicit stages: O0,
immediately after compaction, at the stable ResetRequired page, at recovered
Live, after controller stop and after child-process reap. Every sample is
exactly equal to O0. The fixture uses a same-position wake before compaction to
make the old Task read deterministic; there is no notifier publication after
compaction and therefore no synthetic Reset trigger.

## Read-only Authority oracle

`fault-conformance::r9b_governed_state` opens the frozen Task and Policy owner
stores with `SQLITE_OPEN_READ_ONLY`, verifies SQLCipher, enables `query_only`
and starts a deferred read transaction. It validates the fixed store epoch,
schema profile, event sequence and exact table allowlist, then computes a
canonical row digest for every allowed table.

The two store snapshots are intentionally not described as cross-database
atomic. Repeating this oracle at the required stages proves durable
before/after equality without introducing a writer, migration path or product
capability.

## Deterministic cleanup and safety

- Child readiness, client attach, page observation, barrier waits, controller
  stop and process shutdown/reap all have explicit deadlines.
- Control files are created once and synchronized before use.
- The same `Arc<ClientAttachment>` is retained by the production controller.
- The retention fixture never writes raw SQL and never constructs a fake
  ResetRequired frame.
- Final process inspection reports no remaining EgoPulse daemon or fixture
  process.

## Local verification

The stable candidate has passed:

```text
cargo check -p egopulse-agentosd --test c5_00_daemon_fixture

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture r9b_real_windows_dual_state_cli_tui_and_same_root_restart_are_consistent -- --exact --nocapture --test-threads=1
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture r9b_read_permission_rejection_is_isolated_to_one_domain -- --exact --nocapture --test-threads=1
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture r9b_task_stream_single_disconnect_keeps_approval_live_and_recovers_bounded -- --exact --nocapture --test-threads=1
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture r9b_retention_gap_resets_only_task_and_rebaselines_bounded -- --exact --nocapture --test-threads=1

cargo test -p egopulse-v01-fault-conformance r9b_governed_state -- --nocapture --test-threads=1
cargo clippy -p egopulse-agentosd --test c5_00_daemon_fixture -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Each C5 exact scenario passed with one selected test and zero failures. The
oracle suite passed five tests. Independent implementation, test and
architecture reviews report no P0 or P1 issue. Windows linking may emit the
existing missing `ossl_static.pdb` LNK4099 debug-symbol warning; it does not
change the successful result.

The final local repository gate recorded `status=passed`,
`duration_ms=125353`, with 7/7 stages passing:
`git-diff-integrity`, `locked-node-manifest`,
`contracts-boundaries-typescript`, `rust-workspace`,
`python-foundation-probe`, `python-contract-bindings` and
`python-memory-rag`. The serial C5 suite inside the Rust workspace passed all
36 tests, and final process inspection found no remaining EgoPulse daemon or
fixture process.

The refreshed contract manifest SHA-256 is
`d64dd4fa35a1fc5f3409d20cfdc192ac7aad9997b73d1c7394b5df5a0a91e5a0`.
Import verification reports 251 artifacts and 185 fixtures; cross-language
code generation reports all 44 generated files clean. The complete local
contract, boundary, code-generation and import checks passed.

## Explicit boundary

This evidence closes the frozen R-9B real-process scenarios and Gate 9. It does
not claim a hard-kill crash window, a cross-domain atomic snapshot, a global
cursor, coordinated Task/Approval ordering, an Authority mutation surface,
R-9C Harness content disclosure, Provider routing, Memory/RAG mutation,
Desktop behavior or packaged release.
