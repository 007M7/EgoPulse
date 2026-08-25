# Phase 2-05 Rust Memory Authority implementation

## Status

Implemented as an internal cognition-runtime slice and opened by the
production daemon composition root. This is not a new V-01 Proto contract,
does not add public API methods and does not claim that the Python Worker is
wired to the daemon.

## Governance boundary

```text
Agent / Model / Harness
        | submit candidate only
        v
Rust Memory Authority (single writer + SQLCipher + audit)
        | Founder evidence -> accept
        | governance/recovery evidence -> revoke
        v
accepted scoped snapshot + snapshot digest
        |
        v
read-only Python retrieval candidate
```

The authority owns the Memory fact, content digest, source reference, scope,
state, revision, persistence, idempotency and event history. A direct Agent
write cannot select `accepted`; it can only create `candidate`. Accepted
content is not edited in place. A correction creates a new candidate and the
old fact can be revoked. `revoked` is terminal.

| Operation | Allowed principals | Required proof | Result |
|---|---|---|---|
| Submit candidate | Founder, Founder Authority, Agent, Model, Harness | authenticated principal and idempotency key | revision 1, `candidate` |
| Accept | Founder, Founder Authority | expected revision and non-empty evidence reference | next revision, `accepted` |
| Revoke | Founder, Founder Authority, Governance Kernel, Recovery Coordinator | expected revision and non-empty evidence reference | next revision, terminal `revoked` |
| Retrieval snapshot | read side of the Rust authority | exact scope | accepted records plus snapshot digest |

The Governance Kernel may enforce a revocation policy but cannot silently
promote a candidate. Founder-controlled acceptance remains the final authority
for turning a proposal into durable memory truth.

## Persistence and failure behavior

The implementation follows the existing Task Authority SQLCipher pattern, but
uses a separate Memory database schema and store epoch. Each mutation commits
the Memory row, audit event, idempotency result and metadata sequence in one
SQLite immediate transaction. Replaying the same principal/operation/key with
the same request digest returns the original receipt; reusing it with changed
input fails closed. Stale revisions, missing evidence, unauthenticated
principals and terminal-state transitions fail without a write.

The accepted snapshot is sorted by `memory_id` and has a deterministic digest
over scope, revision, content digest, provenance and state. This lets the
future Python boundary prove which accepted view it consumed without giving
the Worker a database handle.

## Selection rationale and cost

Rust is used for the Authority because state ownership, authorization,
transactional persistence and audit are quality-critical, global decisions.
The cost is slower iteration for experimental memory algorithms and a later
Rust-to-Python serialization boundary. That cost is deliberate: changing a
retrieval model must not change who owns Memory truth.

SQLCipher is reused because the project already has a verified local encrypted
store pattern and Windows-first local deployment requires no server service.
The cost is native build/link complexity and key lifecycle responsibility;
those remain explicit deployment concerns rather than being hidden in the
Python Worker.

## Not yet frozen

- the public Memory API and cross-language Protobuf messages;
- embedding model, vector index, reranker or LangChain/LangGraph dependency;
- Memory commands and read projections for CLI/TUI;
- compaction, retention and user-facing export/import policy.

Each item requires its own contract/evaluation record rather than being
silently added to this internal Authority slice.

## Verification evidence

`crates/cognition-runtime/tests/memory_authority.rs` covers six paths:
candidate-only writes and Founder acceptance, unauthorized/missing-evidence
rejection, idempotency replay/conflict, terminal revocation and stale revision,
encrypted-store reopen, and unauthenticated identity rejection. The crate's
existing Task Authority tests remain green, and the crate passes Clippy with
`-D warnings`.
