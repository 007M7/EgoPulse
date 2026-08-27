# Phase 2-14 Memory project evaluation corpus

- Status: `representative_small_corpus_two_candidates_measured_not_admitted`
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

## Two-candidate local comparison

Both candidates were run through the same offline adapter, unchanged dataset
digest and `K=2` evaluation. The runs were local-only on Windows x64; no
network request, Memory write or persistent vector index was used.

| Candidate profile | Semantic Recall@2 | Semantic MRR | Semantic nDCG@2 | Hybrid Recall@2 | Hybrid MRR | Hybrid nDCG@2 | Peak working set | Snapshot |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `paraphrase-multilingual-minilm-v0` | 0.92857143 | 0.78571429 | 0.82312279 | 0.85714286 | 0.78571429 | 0.80441854 | 597 MiB | 252,138,706 B |
| `multilingual-e5-small-v0` | 1.00000000 | 0.89285714 | 0.92091352 | 0.92857143 | 0.82142857 | 0.84948495 | 911 MiB | 487,352,505 B |
| lexical baseline | — | — | — | 1.00000000 | 0.82142857 | 0.86818920 | negligible | — |

The E5 semantic profile is the strongest measured retrieval candidate: it
retains lexical Recall@2 and improves MRR and nDCG. Its fixed equal-weight RRF
fusion is not admissible because Recall@2 falls to `0.92857143` and nDCG also
falls below the lexical baseline. MiniLM is not admissible on this corpus:
both its semantic and hybrid profiles regress Recall@2, with the hybrid losing
the `en-memory-truth-owner` and `en-worker-write-boundary` cases.

Candidate identities and measured costs:

- `paraphrase-multilingual-minilm-v0`: model
  `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`, dimensions
  `384`, Apache-2.0, ONNX SHA-256
  `634d0f66c29dc934c8fa72b8a4fe91dd4d420a22f1d82a241058d4316e659a99`;
  model artifact `235,052,644` B; snapshot revision
  `faf4aa4225822f3bc6376869cb1164e8e3feedd0`.
- `multilingual-e5-small-v0`: model `intfloat/multilingual-e5-small`,
  dimensions `384`, MIT, ONNX SHA-256
  `ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665`;
  model artifact `470,268,510` B; snapshot revision
  `614241f622f53c4eeff9890bdc4f31cfecc418b3`.
- Both used `fastembed==0.8.0;onnxruntime==1.29.0` with CPU execution. E5's
  measured peak working set is materially higher, so its quality lead carries
  a real Windows packaging and runtime cost.

The exact run command for either candidate is:

```powershell
$env:PYTHONPATH = "workers/memory-rag/src;workers/contract-bindings/src"
& ".\workers\memory-rag\.venv\Scripts\python.exe" `
  -m egopulse_memory_rag.model_evaluation `
  --dataset workers/memory-rag/evaluation/project-boundaries-v0.json `
  --model <candidate-alias> --cache-dir .cache/fastembed `
  --threads 2 --k 2 --local-files-only
```

The experiment therefore closes the “two candidates measured” evidence row,
not the production technology decision. No embedding model, RRF weighting,
vector store or reranker is frozen. The current production fallback remains
`lexical-overlap-v0`; E5 is the candidate for a later Founder review because
its semantic-only profile meets the measured quality threshold but still needs
an explicit product cost decision and a production-profile contract.

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
