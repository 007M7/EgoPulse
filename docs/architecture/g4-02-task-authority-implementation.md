# G4-02 Task Authority implementation profile

- Status: active Gate 4 work package
- Date: 2026-08-23
- Frozen inputs: C-01 Task Contract, C-08 Persistence/Recovery Contract, Feature ADR A
- Scope: one durable `CreateTask` write path plus fail-closed duplicate, stale, unauthorized and recovery behavior

## Boundary

`cognition-runtime::task_authority` owns the V-01 Task store and is the only module allowed to mutate it. The SQL connection and schema module remain private. `agentosd` may host the module, but the deployment host, Local API, UI, Harness, Sego and Python workers receive no database handle or repository write API.

G4-02 does not claim the later Task transitions are implemented. Recognized commands outside the completed `CreateTask` path may be rejected by authentication, authorization, revision or dependency-validation gates, but cannot mutate Task state until their owning work package supplies the required cross-domain proof.

## Persistence choice

Use exact `rusqlite 0.40.2` with `bundled-sqlcipher-vendored-openssl`, matching the Gate 3 fault-conformance toolchain, and `rusqlite_migration 2.6.0` for embedded forward migrations.

Why this choice:

- C-08 requires local SQLCipher/SQLite, explicit transactions and observable durability settings. Rusqlite exposes those controls directly without an ORM unit-of-work layer.
- The Authority is deliberately single-writer. A synchronous connection owned by one mutable Rust module expresses that invariant more directly than an async pool.
- The bundled SQLCipher profile avoids silently linking a plaintext system SQLite or depending on machine-specific SQLCipher/OpenSSL installation.
- `rusqlite_migration 2.6.0` tracks rusqlite 0.40 and keeps migrations embedded in the binary. The store additionally records an implementation schema profile digest because `user_version` alone is not sufficient recovery evidence.

What this gives up and where the cost appears:

- Bundled SQLCipher and vendored OpenSSL increase build time, binary size, security-update responsibility and license inventory work.
- Rusqlite connections are not an async query pool. Calls must stay on the Authority's serialized lane; later Local API integration must not block an async executor thread with arbitrary database work.
- `rusqlite_migration` uses SQLite `user_version` and does not retain a rich migration history table. EgoPulse must keep schema profile digests, coordinated pre-upgrade manifests and migration evidence required by C-08.
- SQLx was not selected because compile-time query metadata and async pooling do not improve the single-writer local Authority, while SQLCipher linkage/configuration remains an extra concern. Diesel was not selected because its ORM abstraction does not remove the need to reason explicitly about state/event/idempotency/outbox atomicity. Refinery 0.9.2 was not selected because its current rusqlite range stops at 0.39, while the accepted and current SQLCipher driver is 0.40.2.

## Atomic commit set

One successful create transaction writes exactly:

1. current Task snapshot at `revision=1/work_revision=1`;
2. one append-only `TASK_EVENT_KIND_CREATED` event;
3. one idempotency result keyed by authenticated principal, operation, scope and key;
4. one stable outbox message carrying the committed Task event for a future owning consumer;
5. the Task-domain watermark and commit receipt metadata.

The command result is returned only after transaction commit with SQLCipher active, WAL journaling, `synchronous=FULL` and foreign keys enabled. This is process-crash durability evidence, not yet a Gate 6 physical power-loss claim.

## Validation order

```text
authenticated OS-derived principal
  -> operation permission
  -> required metadata and canonical request digest
  -> idempotency lookup
  -> expected revision (when present)
  -> state/reference/contract proof
  -> one owner transaction
  -> durability barrier
  -> response
```

Caller bodies never provide trusted actor or authority values. Duplicate same-key/same-digest requests replay the committed result with zero write. Same key with a different canonical digest, stale revision, unauthorized principal, unverified reference and store integrity failure all fail closed.

## Exit tests

- valid encrypted create and exact atomic row set;
- duplicate replay and idempotency conflict with unchanged counts;
- stale expected revision with unchanged counts;
- Harness terminal-write attempt with unchanged counts;
- close/reopen recovery and encrypted file-header proof;
- child-process abort after commit/before response, followed by replay with no second revision/event/outbox row;
- dependency boundary check proving UI/Harness/Worker code cannot import private Task storage.
