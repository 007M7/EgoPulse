# Phase 2.36 — Semantic RAG production admission review

Status: decision required; lexical RAG remains the release default

## Current capability

EgoPulse already has a production RAG path: Rust Memory Authority provides an
accepted, scope-bound snapshot and the Python Worker performs deterministic
lexical retrieval over that snapshot. The Worker has no database handle and no
mutation capability.

Semantic retrieval is an implementation profile behind that read-only Worker
boundary. It is not a new authority, a new memory store, or a reason to add a
vector database to the product.

```text
Memory Authority
  -> accepted snapshot
  -> read-only Worker profile
       -> lexical-overlap-v0        [release default]
       -> semantic-e5-small-v0      [quality candidate, not admitted]
       -> hybrid profile             [experiment only]
```

## Evidence-based choice

### Why lexical-overlap-v0 is the release default

It is the only profile that currently satisfies the product's local-first
resource boundary without an additional model artifact. It is deterministic,
offline, fast to start, easy to reproduce, and keeps the Windows package small.
It also preserves the strongest operational property of the current Worker:
the accepted snapshot is the complete input and the algorithm identity is
explicit in the request and response.

The cost is quality: paraphrases, multilingual semantic similarity and terms
with weak lexical overlap can be missed. This is a product-quality limitation,
not a hidden correctness failure, and it is visible in the algorithm profile.

### Why multilingual-e5-small-v0 is the only current semantic candidate

The recorded project-boundaries evaluation showed the best retrieval quality:
Recall@2 `1.00000000`, MRR `0.89285714` and nDCG@2 `0.92091352`. It also has an
MIT model license and an ONNX execution path that avoids adding PyTorch to the
Worker.

The price is substantial for a local Windows desktop: the model snapshot is
about 487 MB, measured peak working set was about 956 MB, and the Worker needs
the E5-specific `query:` / `passage:` preprocessing rule. Packaging, update
verification, cold-start time and coexistence with one or more Harness
processes all become release concerns. These are real costs even though the
model is technically functional.

### Why MiniLM is not selected

MiniLM is smaller, but its measured Recall@2 and ranking metrics regressed
against the lexical baseline. Saving model bytes while lowering retrieval
quality does not meet the no-regression rule.

## Admission decision

No semantic profile is silently promoted by this document. The current
release remains:

- Memory Authority: production;
- accepted-snapshot boundary: production;
- lexical-overlap-v0: production default;
- multilingual-e5-small-v0: quality candidate pending an explicit packaging
  decision;
- hybrid/RRF and reranking: experiment only.

This keeps the frozen architecture stable. The Worker contract is already the
replaceable boundary; changing the retrieval profile does not change memory
ownership, candidate governance, accepted snapshots, or the three client
surfaces.

## Required Founder choice

There are two viable product choices:

1. **Ship E5-small as an opt-in local semantic profile.** This provides the
   quality improvement while keeping lexical retrieval as the low-cost default.
   It requires a separately hashed model package, installer/update size
   acceptance, a memory-budget warning, offline model verification and a
   production dependency change from evaluation-only FastEmbed.
2. **Keep lexical-only for the first Windows release.** This minimizes package
   size and memory use. E5 evaluation remains reproducible and can be promoted
   later without changing the authority architecture, but semantic retrieval
   will not be available to first-release users.

The decision cannot be inferred from code because it changes the user-facing
package size, local resource requirements and feature promise. Until one is
selected, the existing lexical-only release claim is the accurate one.

## Evidence source

Detailed measurements, full artifact digests, E5 preprocessing rules and the
reproduction command are recorded in
`docs/architecture/phase-2-15-memory-real-model-comparison.md`.
