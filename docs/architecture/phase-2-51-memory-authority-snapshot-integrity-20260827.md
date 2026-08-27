# Phase 2-51: Memory Authority snapshot integrity and resource boundary

- Date: 2026-08-27
- Scope: Rust Memory Authority candidate intake and accepted-snapshot export
- Status: implemented and locally verified
- Admission impact: none; lexical retrieval remains the default

## Finding

The Python Worker already validates accepted-record digests and retrieval
resource limits. That validation happened after Rust had materialized the
accepted scope, so it was not sufficient to protect the daemon from an
oversized or semantically inconsistent store row.

## Delivered controls

1. `MemoryAuthority` recomputes `content_sha256` whenever a stored row becomes
   a public `MemoryRecord`. A SQLCipher structural integrity result of `ok` is
   therefore not treated as proof that denormalized content and digest fields
   agree.
2. Candidate intake rejects content larger than the frozen retrieval content
   boundary and rejects memory, source and scope identifiers larger than the
   frozen routing-field boundary.
3. Accepted snapshot export performs a SQL-side preflight for record count,
   total content bytes and maximum routing-field bytes before loading record
   contents into Rust memory. Any exceeded bound fails closed as an Authority
   storage failure; no partial snapshot is returned.
4. The existing Worker boundary remains unchanged and repeats digest, state,
   scope and resource validation before inference.

## Evidence

```text
cargo fmt --all -- --check
passed

cargo test -p egopulse-cognition-runtime --lib --test memory_authority
unit tests: 4 passed
Memory Authority integration tests: 7 passed
```

The tests cover matching and drifted content digests, encrypted-store
reopen, candidate-only writes, idempotency, terminal revocation,
unauthenticated writes, and oversized candidate content/routing fields.

## Non-claims

This change does not make a semantic/vector algorithm production-ready, does
not add an embedding index, and does not promote any Provider or model. It
only ensures that the frozen accepted-snapshot boundary is checked before a
replaceable Worker receives data.
