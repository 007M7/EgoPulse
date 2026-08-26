# Phase 2-12 Memory retrieval evaluation gate

- Status: `experiment_gate_implemented_baseline_recorded`
- Date: 2026-08-26
- Production impact: none; `lexical-overlap-v0` remains the only admitted profile
- Predecessors: M-01 through M-10

## Decision boundary

M-01 through M-10 froze Memory ownership, accepted-snapshot input,
reference-only output, scope isolation, bounded supervised execution and
fail-closed validation. They deliberately did not freeze an embedding model,
vector database, ANN index, reranker or framework.

Phase 2-12 adds an offline evaluation gate around that replaceable algorithm
boundary. It does not revise `egopulse.memory.v1`, install a new production
algorithm profile, persist an index or grant Python a Memory write path.

The stable architecture remains:

```text
Rust Memory Authority accepted snapshot
                 |
                 v
replaceable Python retrieval candidate
                 |
                 v
reference-only, digest-bound result
                 |
                 v
Rust integrity and scope validation
```

Embedding generation, exact vector scoring, ANN, graph expansion and reranking
are implementation candidates behind the middle boundary. None becomes a
Memory fact owner.

## Why an evaluation gate comes before a vector database

The frozen request already contains at most 2,048 accepted records and 8 MiB
of content. A persistent vector database would introduce a second lifecycle,
index freshness, deletion/revocation propagation and recovery obligations
before the product has measured whether exact in-memory scoring is inadequate.
It would also fail to answer which embedding or fusion strategy improves the
actual Memory workload.

The evaluation gate answers the prior question: does a candidate improve
retrieval quality while preserving reference integrity, determinism, scope and
resource limits? Only measured candidates should trigger a later storage or
wire-contract decision.

The cost is that Phase 2-12 does not itself deliver semantic retrieval to
users. It creates reproducible evidence and prevents a high-lock-in database
choice from substituting for retrieval quality.

## Implemented evaluator

`workers/memory-rag/src/egopulse_memory_rag/evaluation.py`:

- accepts a versioned JSON fixture containing synthetic queries, accepted
  records and relevance labels;
- runs every candidate twice and rejects nondeterministic results;
- rejects unknown or duplicate Memory references, query-digest drift,
  source/content digest drift, invalid scores and result-limit violations;
- reports Recall@K, mean reciprocal rank and nDCG@K;
- emits dataset identity and a canonical dataset SHA-256;
- excludes raw queries and Memory content from the result report.

The evaluator is offline product engineering support. It does not open
SQLCipher, call the daemon, make a network request or write a Memory fact.

## Baseline evidence

The reproducible command is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/evaluate-memory-retrieval.ps1 `
  -DatasetPath workers/memory-rag/evaluation/baseline-v0.json `
  -K 2
```

Dataset:

- ID: `egopulse-memory-retrieval-smoke-v0`
- SHA-256: `56800195e6fea8a8716087593d492fc0a04b29c61d90f076037378a80d5d2f56`
- Cases: 2 synthetic, non-sensitive cases

`lexical-overlap-v0` result:

| Metric | Result |
|---|---:|
| Recall@2 | 0.5 |
| Mean reciprocal rank | 0.5 |
| nDCG@2 | 0.5 |
| Exact lexical case recall | 1.0 |
| Semantic paraphrase case recall | 0.0 |

This is a smoke baseline, not a product-quality corpus claim. It proves the
known semantic recall gap and validates the evaluator mechanics. It cannot
rank embedding models or justify production admission by itself.

## Candidate admission sequence

1. Add representative, versioned, non-sensitive English and Chinese Memory
   cases with relevance judgments and difficult negatives.
2. Implement exact in-memory embedding scoring as an experiment adapter; do
   not add a persistent vector store in the first comparison.
3. Compare lexical, semantic and reciprocal-rank-fused hybrid retrieval under
   the same dataset, limits and reference-integrity checks.
4. Add a reranker candidate only after the first-stage recall comparison;
   measure its latency, model footprint and offline packaging cost separately.
5. Present the measured model/runtime/storage trade-off to Founder. A new
   production `algorithm_profile` or persistent index requires an explicit
   contract and architecture decision.

## Rejection and rollback

- A candidate that violates references, scope, determinism or bounds is
  rejected regardless of quality score.
- A quality regression cannot be hidden by changing the dataset digest.
- Removing Phase 2-12 deletes only evaluator code and synthetic fixtures; no
  production data or contract migration is required.
- `lexical-overlap-v0` remains the production fallback until a later Founder
  admission decision is implemented and verified.
