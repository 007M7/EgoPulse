# Phase 2-04 Memory/RAG Worker boundary

## Status

This is an implementation candidate for the Python cognition boundary. It is
not a new V-01 Protobuf contract and does not change the frozen authority
schema.

## Ownership

```text
Rust Memory Authority / Context Compiler
        |  accepted records + scope + content digest
        v
Python Memory/RAG Worker
        |  ranked memory references + algorithm/evidence digest
        v
Rust Context Compiler / governed Harness dispatch
```

The Rust side remains the owner of Memory truth, lifecycle, scope, provenance,
acceptance/revocation and persistence. The Python Worker is a read-only
consumer. It cannot create, mutate, accept, revoke or promote a memory fact,
and it has no database handle.

## First implementation slice

`workers/memory-rag` implements a dependency-free lexical baseline:

- verifies every supplied record's content SHA-256 before use;
- accepts only records already marked `accepted` and in the requested scope;
- returns memory IDs, source references, content digests, scores and matched
  terms, not authoritative content ownership;
- uses deterministic tokenization, smoothed IDF weighting, salience as a small
  bounded tie-break signal, and memory ID tie-breaking;
- emits a deterministic evidence digest for the request and ranked result;
- rejects malformed, duplicated, tampered, over-sized or out-of-scope input.

This baseline is intentionally not called semantic retrieval and does not
freeze an embedding model, vector database or LangChain/LangGraph runtime.
Those choices require a separate evaluation record covering model identity,
index ownership, rebuild/versioning, cost and rollback. A future embedding or
reranker must remain behind this read-only boundary and must not become a
Memory Authority.

## Selection rationale and cost

Python is used here because the cognition plane already reserves Python for
parsing, model experiments and evaluation, and because an isolated `uv`
project keeps those fast-changing dependencies out of the Rust authority and
the TypeScript client. The immediate cost is one more runtime boundary and a
future cross-language contract to maintain; that cost is accepted only for
experimental cognition code, not for authoritative state.

The lexical baseline is selected because it is dependency-free, reproducible,
easy to inspect in a failing fixture and cheap to run on a local Windows
installation. It gives up semantic recall, multilingual quality and large
corpus performance compared with embeddings plus a vector index. Those are
known product costs, not hidden architecture decisions. They must be measured
against representative local data before an embedding model, vector store or
framework is admitted.

LangChain and LangGraph are therefore not dependencies of this worker. They
remain possible cognition-plane implementation tools, but selecting either
would introduce framework lifecycle, upgrade and observability coupling before
the Memory Authority and retrieval contract are frozen.

## Acceptance evidence

The local tests cover normal ranking, scope/state filtering, digest mismatch,
duplicate identity, invalid request limits and deterministic tie/evidence
replay. The worker has no persistence dependency and therefore cannot silently
write Memory facts during retrieval.
