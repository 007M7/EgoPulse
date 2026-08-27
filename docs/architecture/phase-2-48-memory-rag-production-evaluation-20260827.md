# Phase 2-48 Memory/RAG production evaluation baseline

- Date: 2026-08-27
- Scope: governed Memory Authority input and replaceable retrieval Worker
- Decision: retain lexical baseline as production default; semantic retrieval remains experimental

## Evaluated boundary

The Rust Memory Authority remains the only owner of durable Memory truth and
the only writer that can accept or revoke a record. The Python Worker receives
one bounded accepted snapshot and returns references plus an evidence digest.
It has no database handle and cannot mutate Memory state.

The evaluation therefore measures retrieval quality and determinism only. It
does not grant the Worker authority and it does not make an embedding index a
source of truth.

## Baseline command and result

```powershell
$env:PYTHONPATH = 'workers/memory-rag/src;workers/contract-bindings/src'
uv run --project workers/memory-rag --frozen python -m egopulse_memory_rag.evaluation `
  --dataset workers/memory-rag/evaluation/project-boundaries-v0.json --k 2
```

Observed result:

```text
dataset_id       = egopulse-project-boundaries-v0
dataset_sha256   = d38307e1896ad7a969078f9e2bf3dc721e8450e84ca08a46cc6653bb4a4156ff
algorithm_id     = lexical-overlap-v0
case_count       = 14
recall_at_k      = 1.0
mean_reciprocal_rank = 0.82142857
ndcg_at_k        = 0.8681892
```

The run is deterministic and all 14 cases satisfy the accepted-state,
scope, digest and resource limits. The score must be treated as a baseline
for this architecture corpus, not as a claim of general semantic retrieval
quality. The separate paraphrase-smoke case remains the reason semantic
retrieval is not the default.

## Production governance rules

1. Accepted/revoked/candidate state is checked before every retrieval run.
2. Scope authorization is decided by the daemon from the authenticated
   principal; the Worker only repeats scope and digest validation.
3. A new algorithm must preserve the same input/output boundary and return an
   algorithm identity, model identity when applicable, and evidence digest.
4. A semantic or hybrid candidate must be evaluated on the same project
   corpus, with local-files-only and resource-budget runs before any download
   or user-facing default.
5. Quality improvement alone cannot promote a Worker: authority isolation,
   deterministic failure behavior, bounded resources and rollback to
   `lexical-overlap-v0` are required.

## Next Memory/RAG gate

The next implementation slice is a candidate evaluation gate, not a change to
Memory Authority: record model/cache provenance, compare lexical/semantic/
hybrid reports, enforce deterministic replay, and emit a fail-closed decision
when the pinned model artifact or local cache is unavailable. Only after that
evidence is complete should a semantic Worker be considered for opt-in use.

