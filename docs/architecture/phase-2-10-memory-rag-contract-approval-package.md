# Phase 2-10 Memory/RAG contract approval package

## Status

Founder-approved implementation package. M-01 through M-06 and the initial
limits are frozen in `egopulse.memory.v1` draft.15; generated Rust, Python and
TypeScript bindings, the supervised Python adapter and Rust boundary validation
are implemented. The document remains the decision record for the boundary;
the public daemon workflow is still a later slice.

The implementation boundary is intentionally narrow: Rust owns accepted
Memory state and snapshot identity; the Python Worker performs bounded
retrieval over a supplied snapshot; Rust validates the returned references
before context construction. The Worker never opens SQLCipher and never
creates, accepts or revokes Memory facts.

## Decisions requested

| ID | Decision | Proposed default | Why this is a contract decision | Cost accepted |
|---|---|---|---|---|
| M-01 | Memory input ownership | Rust supplies only accepted, scope-bound records and an exact snapshot digest | It determines what information a Worker is allowed to see and what snapshot a response means | Snapshot materialization and transfer add per-request copying and a hard size limit |
| M-02 | Worker output shape | Worker returns ranked references, source/content digests and one evidence digest; it does not return authoritative Memory content | It prevents algorithm output from becoming Memory truth and lets Rust resolve content under policy | Rust needs a second resolution step and cannot treat a Worker response as ready-to-send prompt text |
| M-03 | First transport | Length-delimited Protobuf over the existing supervised stdin/stdout boundary | It reuses the repository's Buf/protoc source and existing Windows process ownership/fault model | Worker startup and explicit crash/timeout/cancel recovery are required |
| M-04 | Retrieval baseline | `lexical-overlap-v0` with deterministic ordering and bounded limits | It gives an explainable, reproducible acceptance baseline before semantic quality experiments | It will miss semantic matches and is not the final retrieval quality target |
| M-05 | Framework boundary | Keep the pure Python algorithm core; evaluate LangChain/LangGraph, embeddings, rerankers and indexes behind the adapter | These are replaceable cognition implementations, not authority or wire-contract ownership | The adapter must translate every candidate and preserve the same invariants across implementations |
| M-06 | Persistence boundary | SQLCipher Memory Authority remains Rust single-writer; the first Worker has no persistence dependency | It protects governance, encryption, recovery and idempotency from Python runtime variation | Retrieval starts from a bounded snapshot instead of an always-hot external index |

## Deliberately not frozen

The following choices remain experiments and must not be encoded as V-01 or
Memory contract semantics:

- embedding model, vector database or ANN index;
- reranker model or tokenizer;
- LangChain/LangGraph graph topology;
- chunking, summarization or compaction policy;
- Memory retention, export/import and user-facing editing policy;
- a second local service or network endpoint for the Worker.

An experiment may propose a new `algorithm_profile`, but it cannot change
snapshot ownership, reference integrity, scope isolation, deterministic
ordering, evidence binding or fail-closed process behavior.

## Acceptance limits for the first contract draft

These are implementation limits of the first frozen contract, not quality
claims about future retrieval:

| Limit | Initial value | Purpose |
|---|---:|---|
| Query bytes | 16 KiB | Bounds request memory and framing cost |
| Scope/algorithm/ID bytes | 4 KiB each | Rejects unbounded routing metadata |
| Accepted records per request | 2,048 | Bounds snapshot traversal |
| Total supplied content bytes | 8 MiB | Bounds Worker input and prompt-adjacent data |
| Returned candidates | 64 | Bounds response and downstream context work |
| Worker frame | 16 MiB | Reuses `process-supervision` default frame ceiling |
| Worker execution time | 30 seconds | Makes timeout and recovery observable on Windows |

Rust may lower a limit for a particular workflow. A Worker cannot raise one
through configuration or a model/provider response.

## Evidence completed before daemon wiring

The implementation unit produced the following locally on Windows x64:

1. Buf/protoc generation for Rust, Python and TypeScript from one Proto source;
2. request/response round trips with deterministic digest fixtures;
3. malformed, duplicate, out-of-scope, oversized and digest-mismatch rejection;
4. Worker crash, timeout, snapshot-drift and truncated-frame evidence through
   the existing supervisor;
5. replay evidence proving the same request/snapshot produces the same ordered
   candidate identity and evidence digest;
6. daemon composition only after the above checks pass.

The first implementation must not add a Memory write command to CLI, TUI or
TypeScript. Memory writes remain governed Rust operations with explicit
principal, revision, idempotency and evidence checks; the client surfaces may
be added only after those operations have their own approved contract.

## Founder approval record

Founder approval recorded on 2026-08-26: M-01 through M-06 and the initial
limits above are accepted and frozen. The implementation authority reference
is `conversation:2026-08-26:founder-memory-rag-m01-m06-freeze`. This authorizes
generation, commit and push of Rust, Python and TypeScript bindings. It does
not authorize embedding/index selection, a Python write path, or public
daemon/API wiring without a separate contract decision.

Related proposal: `phase-2-06-memory-rag-cross-language-contract-proposal.md`.
