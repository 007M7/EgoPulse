# Phase 2-14 Memory project evaluation corpus

- Status: `representative_small_corpus_recorded_model_runs_pending`
- Date: 2026-08-26
- Production impact: none
- Predecessors: Phase 2-12 evaluation gate and Phase 2-13 experiment adapters

## Outcome

`workers/memory-rag/evaluation/project-boundaries-v0.json` records the first
versioned, non-sensitive evaluation corpus derived from actual EgoPulse
architecture and contract decisions. It replaces the two-case smoke fixture as
the working comparison set, while retaining that fixture for evaluator
conformance tests.

The corpus contains 14 relevance-labelled cases:

| Slice | Cases | Covered boundaries |
|---|---:|---|
| English | 8 | Memory truth owner, Python write boundary, shared CLI/TUI kernel, Founder promotion, accepted-snapshot admission, vector-index authority, current production Harness, second-Harness gate |
| Chinese | 6 | Python write boundary, shared CLI/TUI capability, reference-only output, synchronous non-persistent retrieval, daemon authorization, replaceable embedding technology |

Each case includes one relevant fact and two difficult negatives. Negatives
share entities or keywords with the query but answer a different ownership,
state, lifecycle or technology-boundary question. This prevents exact keyword
presence from being treated as sufficient relevance evidence.

## Dataset identity

- ID: `egopulse-project-boundaries-v0`
- Canonical SHA-256:
  `d38307e1896ad7a969078f9e2bf3dc721e8450e84ca08a46cc6653bb4a4156ff`
- Cases: 14
- Records per case: 3
- Sensitive or user-derived content: none
- Label source: frozen EgoPulse project decisions through Phase 2-13

Any text, relevance or metadata change produces a different digest. The test
suite locks the dataset identity and lexical baseline, so an apparent quality
improvement cannot silently come from editing labels or easier negatives.

## Lexical baseline

Reproducible command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/evaluate-memory-retrieval.ps1 `
  -DatasetPath workers/memory-rag/evaluation/project-boundaries-v0.json `
  -K 2
```

`lexical-overlap-v0` result:

| Metric | Result |
|---|---:|
| Recall@2 | 1.00000000 |
| Mean reciprocal rank | 0.82142857 |
| nDCG@2 | 0.86818920 |
| Relevant result at rank 2 rather than rank 1 | 5 of 14 cases |

The result shows that lexical retrieval finds the labelled fact within two
positions on this small corpus but misorders five high-overlap cases. The next
model comparison therefore needs to preserve first-stage recall and improve
ordering, rather than merely returning more candidates.

## Admission use

For this corpus, an embedding or hybrid candidate is not better merely because
it returns a semantic match. A production proposal must provide all of the
following on the unchanged dataset digest:

1. no scope, state, reference, digest, determinism or resource-bound failure;
2. Recall@2 no lower than the lexical baseline;
3. MRR and nDCG@2 higher than the lexical baseline, with per-case regressions
   listed rather than hidden by an aggregate;
4. immutable model identity and revision, dimensions and runtime identity;
5. Windows CPU cold-start and steady-state latency, peak working set, model
   artifact size and redistribution-license evidence;
6. lexical, exact semantic and RRF hybrid reports produced from the same
   records and labels.

A reranker is considered only if the measured first-stage hybrid retains
Recall@2 but still has material rank-order errors. This avoids paying model,
latency and packaging cost to repair a recall problem that reranking cannot
solve.

## Limits

This is a project-derived regression corpus, not a user-memory benchmark:

- 14 cases cannot estimate population-level quality;
- each case contains only three records, far below the 2,048-record Worker
  bound;
- labels were authored from known architecture facts and have not undergone
  independent assessor agreement;
- temporal, multi-hop, contradictory, stale and personally phrased memories
  are not yet represented;
- latency and package footprint are not measured by this dataset.

The corpus is sufficient to compare candidate plumbing and known project
terminology. It is not sufficient to freeze an embedding model, vector store,
reranker or production semantic profile.

## Next gate

Run at least two real multilingual embedding candidates through the exact
adapter and RRF fusion, then publish quality and Windows packaging evidence.
Only that measured comparison can support a Founder technology-selection
decision.
