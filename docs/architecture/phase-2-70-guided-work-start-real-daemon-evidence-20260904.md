# U-04c real-daemon guided Work Start evidence

- Date: 2026-09-04
- Scope: real daemon, Windows IPC, production CLI/TUI seams, durable Authority evidence and normal ConPTY interaction
- Status: locally verified
- Parent flow: U-04 Guided Work Start

## Outcome

U-04c exercises the U-04a shared guided operation and the U-04b production
TUI controller against an independent `agentosd` process over the normal
Windows local IPC attachment. It adds no Proto, Local API, Authority, database
schema or daemon runtime behavior.

The evidence covers three independent CLI cases. Editing cancellation uses an
existing valid source, sends no Prepare or Confirm request, and leaves the
complete Context and Task store snapshots unchanged. A blocked case still uses
a missing source; its preview cannot be confirmed and leaves Task Authority
unchanged. A ready preview confirmed through the real CLI creates exactly one
durable Task and returns its authoritative identity.

The production `WorkStartController` and `TaskWatchController` case retains the
same `Arc<ClientAttachment>`. The confirmed Task identity comes only from the
real confirmation result. Task Watch initially has no selection for a missing
target projection, then selects that exact identity after the governed
projection arrives. Neither the controller nor the watch infers completion.

## Outcome-unknown recovery

A test-only `WorkPreparationPort` decorator supplies two separate crash-window
fixtures:

- Prepare committed before its first response becomes unavailable.
- Confirm committed before its first response becomes unavailable.

In both cases the first call invokes the real production port and completes
the Authority commit before returning the existing unavailable failure. The
same active client and attachment retain the opaque recovery capsule. The
second call is accepted only when the encoded request, idempotency key and
authenticated principal are identical; it invokes the real port again and
receives the Authority's idempotent replay result. A drifted request or
principal, or any third call, fails closed.

The synchronized test witness records the daemon PID, operation, request
digest, principal, call count and unchanged durability result. This proves
exact replay by the same live client. It does not prove serialization or
recovery of a capsule by another client process and does not introduce a later,
separately frozen client-recovery contract.

## Read-only durability oracle

`egopulse-v01-fault-conformance::u04c_work_start` opens the Context and Task
SQLCipher stores with `SQLITE_OPEN_READ_ONLY` and `query_only=ON`. It verifies
the cipher and SQLite integrity checks, expected store epoch, exact schema
profile ID and digest, metadata/event sequence agreement, and a fixed complete
table allowlist. Each store is read through one Deferred transaction.

The oracle returns only typed snapshots, fixed table row counts/content
digests and exact selected Context/Task record evidence. The C5 tests compare
the full table snapshot before and after exact replay, prove the valid-source
cancel path leaves both Context and Task stores unchanged, prove the blocked
path does not write Task tables, and prove the happy path adds one Task. Both
the CLI happy path and ConPTY path decode the durable `TaskSnapshot` bytes,
take its `input_snapshot_id`, and use a fresh read-only oracle query to prove
that exactly one matching Context record exists, remains `issued`, and is the
snapshot bound to the Task. It exposes no arbitrary SQL or write capability.

## Real terminal evidence

The ConPTY test launches the normal debug `egopulse-tui.exe`; it does not use a
`--once` mode or a hidden product command. A `cmd.exe` canary first proves the
host ConPTY is usable. The test then sends the real Dashboard `n` action,
enters all four high-level Work fields, reviews the governed preview, confirms
once, and reaches Task Watch.

The terminal helper keeps a bounded four-MiB raw stream for DSR responses and
failure diagnostics. A test-only `vt100` parser reconstructs the 32x140 current
screen, avoiding false checkpoints from stale accumulated repaint bytes. The
pre-confirm Dashboard projection count and durable Task table count are kept
as separate facts. Task Watch must show one more projected Task than the
Dashboard baseline, and its `>` row supplies the exact selected Task identity
that is checked against the read-only durability oracle. Daemon-only Context
content is absent from terminal output; the durable Task-to-issued-Context
binding is reverified, and the Task remains non-Completed.

All daemon, CLI and TUI children have deadlines, kill fallback and bounded
reaping. Fixture roots are removed only after process cleanup.

## Changed files

- `apps/agentosd/tests/c5_00_daemon_fixture.rs`: real CLI, shared-controller,
  exact-replay and ConPTY C5 evidence plus test-only fixture seams.
- `apps/agentosd/Cargo.toml` and `Cargo.lock`: test-only `portable-pty` and
  `vt100` dependencies.
- `contracts/toolchain/fault-conformance/src/u04c_work_start.rs` and
  `src/lib.rs`: fixed read-only Context/Task durability oracle.

## Automated evidence

```text
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u04c_ -- --nocapture --test-threads=1
  4 passed; 0 failed

cargo test --manifest-path contracts/toolchain/fault-conformance/Cargo.toml --lib
  17 passed; 0 failed

cargo clippy -p egopulse-agentosd --all-targets -- -D warnings
  passed

cargo clippy -p egopulse-tui --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

Windows linking emitted the known non-blocking LNK4099 warnings for missing
OpenSSL PDB debug-symbol files. They do not change the test result.

## Evidence boundary

This is local debug-binary evidence for the complete U-04 guided Work Start
vertical across shared operation, CLI, TUI, daemon, Windows IPC and durable
Context/Task stores. It is not packaged-install evidence, release-signing
evidence, Provider or Memory execution evidence, a hard-kill test, or a claim
that a recovery capsule survives a client-process restart. It does not prove
Task completion and does not add automatic retry or replacement preparation.
