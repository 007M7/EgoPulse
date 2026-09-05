# Phase 2-52 semantic RAG candidate evaluation

- Date: 2026-08-27
- Scope: `multilingual-e5-small-v0` with `rrf-hybrid-v0`
- Dataset: `egopulse-project-boundaries-v0`
- Dataset SHA-256: `d38307e1896ad7a969078f9e2bf3dc721e8450e84ca08a46cc6653bb4a4156ff`
- Decision: **rejected for opt-in; retain lexical production route**

## Gate invocation

The candidate was evaluated locally with the locked `fastembed==0.8.0`
dependency and the pinned `intfloat/multilingual-e5-small` snapshot. The model
and evaluation dependencies were downloaded only into the repository's ignored
evaluation cache. No Memory Authority database or accepted Memory state was
changed.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evaluate-memory-gate.ps1 `
  -DatasetPath workers\memory-rag\evaluation\project-boundaries-v0.json `
  -Model multilingual-e5-small-v0 `
  -OutputPath .artifacts\memory-rag\evaluation-gate.json `
  -AllowDownload
```

## Observed result

```text
candidate_algorithm_id = rrf-hybrid-v0:b32a7a65a7ee0d2c
case_count              = 14
k                       = 2
eligible_for_opt_in     = false
default_route_changed   = false
rollback_algorithm_id   = lexical-overlap-v0
reasons                 = quality_regression:recall_at_k,
                          quality_regression:ndcg_at_k
```

| Metric | Lexical baseline | Candidate | Delta |
|---|---:|---:|---:|
| Recall@2 | 1.00000000 | 0.92857143 | -0.07142857 |
| MRR | 0.82142857 | 0.82142857 | 0.00000000 |
| NDCG@2 | 0.86818920 | 0.84948495 | -0.01870425 |

The model artifact was `470,268,510` bytes and its pinned snapshot was
`487,352,505` bytes. Initialization took `54,089.479 ms`; the observed peak
private usage was `1,494,138,880` bytes, within the configured resource limits.
These resource facts are recorded for future comparison, but cannot override
the quality regression.

## Governance consequence

The candidate gate failed closed. The Rust Memory Authority remains the sole
writer and the Python Worker remains read-only. The default retrieval route
did not change, no semantic index became authoritative, and rollback remains
the fixed lexical algorithm. A future candidate must use the same dataset and
protocol and must improve or preserve all gated metrics before it can even
become opt-in eligible; separate Founder activation would still be required.
