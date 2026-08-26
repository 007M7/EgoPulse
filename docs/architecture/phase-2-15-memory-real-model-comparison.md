# Phase 2-15 Memory real embedding comparison

- Status: `candidate_comparison_complete_production_admission_pending`
- Date: 2026-08-26
- Production impact: none; FastEmbed is evaluation-only and no semantic
  profile is admitted
- Dataset: `egopulse-project-boundaries-v0`
- Dataset SHA-256:
  `d38307e1896ad7a969078f9e2bf3dc721e8450e84ca08a46cc6653bb4a4156ff`

## Why FastEmbed was evaluated

The project needs local Windows CPU evaluation without making PyTorch the
Worker's production dependency. Official FastEmbed documentation describes a
lightweight ONNX Runtime path and lists multilingual models, while its PyPI
metadata declares Python 3.14 support. The repository therefore adds
`fastembed==0.8.0` only to the `evaluation` dependency group; the normal
Memory Worker remains lexical-only.

The choice is not an architecture freeze. It is an experiment runtime with a
clear replacement port, explicit model artifact digest and reproducible cache
path.

Official references used for this implementation: [FastEmbed overview](https://qdrant.github.io/fastembed/),
[FastEmbed supported models](https://qdrant.github.io/fastembed/examples/Supported_Models/),
[FastEmbed Python 3.14 package metadata](https://pypi.org/project/fastembed/),
[MiniLM model card](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2),
and [multilingual-E5-small model card](https://huggingface.co/intfloat/multilingual-e5-small).

## Candidates and costs

| Candidate | Role | Artifact / snapshot | Quality result | Cost / decision |
|---|---|---:|---|---|
| `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` | Multilingual ONNX baseline, 384 dimensions, Apache-2.0 | ONNX 235,052,644 bytes; snapshot 252,138,706 bytes; SHA-256 `634d0f...659a99` | Semantic Recall@2 `0.92857143`, MRR `0.78571429`, nDCG@2 `0.82312279`; equal RRF Recall@2 `0.85714286` | Reject: below lexical recall and rank quality; smaller artifact does not compensate for regression |
| `intfloat/multilingual-e5-small` | Multilingual ONNX quality candidate, 384 dimensions, MIT | ONNX 470,268,510 bytes; snapshot 487,352,505 bytes; SHA-256 `ca456c...c8665` | Semantic Recall@2 `1.00000000`, MRR `0.89285714`, nDCG@2 `0.92091352`; weighted RRF (lexical:semantic `1:2`) matches those scores | Hold for Founder packaging decision: quality passes the small-corpus gate, but peak working set was ~956 MB and private usage ~1.47 GB |

The full digests and timing records are emitted by
`scripts/evaluate-memory-model.ps1`. The abbreviated hashes in the table are
only for readability; the implementation pins the full ONNX digest.

## E5 preprocessing finding

E5 is not interchangeable with a symmetric sentence embedder. Its evaluation
provider sends `query: ` before the query and `passage: ` before each record,
and records this as `e5-query-passage-prefix-mean-pooling-v0` in the profile.
The separate `embed_query` / `embed_documents` port is required to keep this
model-family rule explicit and testable.

The model snapshot used in this run was
`614241f622f53c4eeff9890bdc4f31cfecc418b3`; admission evidence additionally
checks the ONNX artifact SHA-256. A model name alone is not treated as an
immutable identity.

## Fusion result

Equal-weight RRF is not accepted as a universal default. On this small
three-record-per-case corpus it reduced E5 Recall@2 from `1.0` to `0.92857143`
because a correct item ranked second in both child lists can lose to two
different first-place negatives when the RRF rank constant is 60.

Weighted RRF with lexical:semantic `1:2` preserved E5's Recall@2, MRR and
nDCG values. Lexical:semantic `2:1` merely reproduced the lexical baseline.
These are experiment observations, not frozen production weights; the
parameter is included in the algorithm identity and evidence digest.

## Acceptance decision

### MiniLM: rejected

It fails the no-regression rule on Recall@2 and does not improve MRR or nDCG.
It remains useful as a low-footprint comparison point.

### E5-small: quality candidate held, not admitted

E5-small is the only candidate in this comparison that clears the retrieval
quality gate. It is not yet a production dependency because its model snapshot
alone is about 487 MB and the measured Windows process memory is large for a
desktop application that must coexist with one or more Harness processes.
The next decision must compare this cost with an explicitly user-authorized
remote embedding mode or a smaller acceptable model; it must not hide the cost
by adding a vector database.

No reranker is added in this phase. First-stage E5 recall is already complete
on the current corpus; a reranker would address ordering at additional model,
latency, license and packaging cost. It should be evaluated only after the
corpus grows and rank errors are shown to be materially representative.

## Reproducibility

After the model cache is populated, run without network access:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/evaluate-memory-model.ps1 `
  -DatasetPath workers/memory-rag/evaluation/project-boundaries-v0.json `
  -Model multilingual-e5-small-v0 `
  -LexicalWeight 1 `
  -SemanticWeight 2
```

The command records quality metrics, model artifact identity, snapshot bytes,
startup/inference timings and Windows working-set measurements. It does not
write Memory, create a vector index, change the Protobuf contract or alter the
production lexical profile.

## Required Founder decision before production use

Choose one of the following explicitly:

1. package E5-small as an opt-in local semantic profile after installer,
   update, model-license and memory-budget evidence;
2. authorize a remote embedding provider with a data-egress consent boundary,
   user-key lifecycle and cost control;
3. keep lexical-only production retrieval until a smaller model clears the
   same corpus and resource gate.

Until that decision is recorded, no model profile is promoted from experiment
to production.
