# Phase 2-06 Memory/RAG cross-language contract proposal

## Status

Historical proposal. M-01 through M-06 were subsequently approved and
implemented as `egopulse.memory.v1` draft.15. This document is retained to
show the alternatives and reasoning that preceded the freeze; its provisional
field numbers are not the current source of truth.

## Required boundary

```text
Rust Memory Authority
  accepted snapshot(scope, records, snapshot_sha256)
        |
        | bounded, one-way read input
        v
Python Memory/RAG Worker
  retrieval request -> ranked references + evidence digest
        |
        v
Rust Context Compiler / Harness dispatch
```

The Worker must not open the SQLCipher database, receive an Authority handle,
or submit a state transition. Rust remains responsible for selecting the
accepted snapshot and validating the returned snapshot/evidence identity.

## Proposed messages

The proposed `egopulse.memory.v1` package would contain the following logical
messages. Names and field numbers are provisional until approval.

```protobuf
message RetrievalRequest {
  string query = 1;
  string scope_ref = 2;
  string snapshot_sha256 = 3;
  uint32 max_results = 4;
  double min_score = 5;
  string algorithm_profile = 6;
}

message AcceptedMemoryInput {
  string memory_id = 1;
  string content = 2;
  string content_sha256 = 3;
  string source_ref = 4;
  string scope_ref = 5;
  uint64 revision = 6;
}

message RetrievalCandidate {
  string memory_id = 1;
  string source_ref = 2;
  string content_sha256 = 3;
  double score = 4;
  repeated string matched_terms = 5;
}

message RetrievalResponse {
  string algorithm_id = 1;
  string query_sha256 = 2;
  string snapshot_sha256 = 3;
  repeated RetrievalCandidate candidates = 4;
  string evidence_ref = 5;
}
```

The response deliberately has no authoritative content field. A caller that
needs content must resolve the selected `memory_id` through the Rust-owned
context compiler, which can apply token budgeting, provenance and policy
again. `snapshot_sha256` binds the response to the exact accepted view that
was supplied to the Worker.

## Invariants to enforce at the boundary

- `query`, `scope_ref`, `snapshot_sha256`, `algorithm_profile` and all IDs are
  non-empty after trimming;
- the request snapshot digest must equal the Rust-produced snapshot digest;
- every input record must be accepted by the Rust snapshot builder, have a
  valid content digest and match the request scope;
- input record count, query bytes and total content bytes have hard limits;
- candidate IDs must be unique, refer only to supplied accepted records and
  carry the original content digest/source reference;
- scores must be finite and in `[0, 1]`; result ordering is deterministic;
- a malformed, oversized, timed-out or digest-mismatched Worker response is
  discarded and never becomes Memory or Task truth;
- Worker process exit, cancellation and protocol-version mismatch fail closed.

These checks belong on both sides where they protect a different trust
boundary: Python validates its own algorithm inputs, while Rust validates the
returned evidence before it is used for context construction.

## Transport alternatives

| Option | Why it could fit | Cost / rejected risk |
|---|---|---|
| Length-delimited Protobuf over a supervised stdin/stdout Worker | Reuses Buf/protoc, no listening port, simple Windows process ownership, one request/response stream | Requires framing, startup cost and explicit process recovery |
| Local gRPC Worker service | Strong streaming/tooling model and familiar generated clients | Adds a second server lifecycle, local endpoint/auth surface and more failure modes for a per-user desktop product |
| JSON Lines over stdin/stdout | Easy to inspect manually and fast to prototype | Duplicate schema validation, weaker numeric/compatibility guarantees and a second contract source |

The current recommendation is length-delimited Protobuf over the existing
process-supervision boundary. The reason is not popularity: it keeps the
Worker ephemeral and owner-controlled while reusing the repository's one
machine-contract source. The cost is accepted only after the Worker process
supervisor proves framing, timeout, cancellation, crash recovery and digest
validation.

## Python and framework boundary

The current `workers/memory-rag` pure function can remain the algorithm core.
A later protocol adapter should translate generated Protobuf messages into its
typed Python request/record objects and back into the response; it must not
move persistence or governance into Python. Embeddings, vector indexes,
rerankers, LangChain or LangGraph can be evaluated behind this adapter, but
none can change the accepted-snapshot or response-evidence invariants.

## Historical approval questions before contract freeze

1. Approve the logical message set and the rule that Rust supplies accepted
   content while the Worker returns references only.
2. Approve length-delimited Protobuf over supervised stdin/stdout as the first
   transport, with local gRPC retained as an evaluated alternative.
3. Approve the initial limits and `lexical-overlap-v0` profile as a testable
   baseline, without freezing an embedding or vector database choice.

Those questions were resolved by the Founder approval recorded in
`phase-2-10-memory-rag-contract-approval-package.md`. The implementation
unit added the Proto source, generated Rust/Python/TypeScript bindings, built
the Worker protocol adapter, and executed real Windows crash/timeout/
snapshot-drift tests before daemon wiring.
