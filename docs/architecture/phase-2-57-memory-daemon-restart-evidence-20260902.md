# Phase 2-57 — Memory fixture-daemon restart evidence

- Date: 2026-09-02
- Scope: Windows C5 fixture daemon, Memory Authority, CLI, TUI and the existing
  supervised lexical Memory retrieval worker
- Status: locally verified as M-12

## Evidence boundary

M-12 proves persistence and replay across a graceful restart of the real C5
fixture daemon. It does not prove packaged-install recovery, daemon hard-kill
recovery, operating-system crash recovery, or an external Provider end-to-end
lifecycle. It does not change or admit a semantic/vector RAG profile.

The evidence uses two separate daemon processes, D1 and D2. They have different
process IDs, use the same DataRoot, and attach through the same test-unique IPC
instance. Both processes are the normal C5 daemon child composition; the test
does not write Memory state directly.

## Scenario and durable facts

In D1, the test submits two distinct Memory candidates. Both are accepted by
the existing Founder-governed mutation path. One record remains accepted
(`memory-m12-kept`), while the other is subsequently revoked
(`memory-m12-revoked`). D1 lexical retrieval returns the kept record and does
not expose the revoked record.

D1 is then closed through its stdin shutdown signal and is waited and reaped
within a fixed deadline. D2 starts with the same DataRoot and IPC instance but
a different PID. After restart:

- CLI retrieval returns the kept record and excludes the revoked record;
- TUI retrieval returns the same result;
- both surfaces return the same complete `snapshotSha256` and `evidenceRef` as
  D1;
- neither response contains the Memory content, and the evidence reference
  retains the existing `memory-rag-evidence-sha256:` form;
- an exact replay of the original revoke command returns the original public
  receipt fields and creates no new durable facts.

## Read-only persistence oracle

The test oracle opens `memory-authority.db` with SQLCipher
`SQLITE_OPEN_READ_ONLY`, enables and verifies `PRAGMA query_only`, requires an
empty `PRAGMA cipher_integrity_check` finding set, and requires
`PRAGMA integrity_check` to return exactly one `ok` row. It never runs a
migration or insert.

Each durable comparison uses one Deferred read-only transaction. The metadata
row is the first business read. Within that same transaction, the oracle:

- verifies the expected store epoch, schema profile and schema digest;
- reads the exact kept and revoked rows, including ID, revision, content,
  content digest, source, scope, state and timestamps;
- recomputes each content SHA-256;
- reads Memory, event and idempotency counts plus `last_event_sequence`;
- verifies `last_event_sequence == max(memory_events.sequence)`.

The complete durable snapshot is unchanged across each read-only retrieval,
across fixture seed replay during D2 startup, and across the post-restart exact
revoke replay.

## Process cleanup

Every M-12 CLI and TUI subprocess has a hard timeout, `kill_on_drop`, and a
bounded kill-and-reap timeout path. D1 and D2 also have bounded graceful
shutdown and panic cleanup guards. The successful test waits and reaps both
daemons, verifies the IPC endpoint is unavailable, and removes the isolated
DataRoot.

## Verification

The focused command passed:

```powershell
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture m12_memory_survives_daemon_restart_with_revocation_replay_and_read_only_retrieval -- --exact --nocapture --test-threads=1
```

Result: `1 passed; 0 failed; 21 filtered out`.

The repository Rust gate also passed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-rust.ps1
```

Its C5 fixture result was `22 passed; 0 failed`.

This is test evidence for the existing lexical Memory path. It is not a claim
that semantic RAG admission, packaged restart, hard-kill recovery or Provider
admission is complete.
