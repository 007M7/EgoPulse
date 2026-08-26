# Phase 2-13 Memory hybrid experiment adapters

- Status: `experiment_adapters_implemented_model_selection_open`
- Date: 2026-08-26
- Production impact: none; `lexical-overlap-v0` remains the only admitted profile
- Predecessor: Phase 2-12 evaluation gate

## Outcome

Phase 2-13 implements two evaluation-only retrieval components behind the
already frozen read-only Worker boundary:

1. exhaustive cosine scoring with an injected embedding provider;
2. reciprocal-rank fusion (RRF) over two independently validated rankings.

This closes the algorithm plumbing needed for a fair lexical, semantic and
hybrid comparison. It does not claim that a particular embedding model is
good, and it does not add a vector database, ANN index, reranker, framework or
new production `algorithm_profile`.

## Stable boundary and replaceable choices

```text
accepted Memory snapshot from Rust Authority
                    |
                    v
       shared invariant validation
                    |
        +-----------+-----------+
        |                       |
        v                       v
 lexical-overlap-v0      injected embedder
                                |
                                v
                       exact cosine ranking
        |                       |
        +-----------+-----------+
                    |
                    v
              validated RRF
                    |
                    v
 reference-only result + evidence digest
```

Architecture-level invariants remain difficult-to-change ownership and
quality boundaries: Rust owns accepted Memory truth, every candidate receives
one bounded scope snapshot, Python is read-only, and returned references are
digest-bound and revalidated. Embedding model, runtime, dimensions, fusion
parameters and later index implementation remain replaceable technology
choices.

## Why exact scoring first

The current Worker receives no more than 2,048 records and 8 MiB of content.
Exhaustive scoring therefore provides a correctness oracle for model
comparison without introducing index freshness, revocation propagation,
rebuild, migration or recovery obligations. ANN or a persistent vector store
can be justified later only by measured latency or corpus-size evidence.

The cost is linear scoring and repeated embedding work. That is acceptable for
the experiment gate but may not be acceptable for a later production profile.
If measurements require an index, exact scoring remains the recall reference
used to quantify ANN loss.

## Why RRF instead of score averaging

Lexical and embedding scores have different distributions and calibration.
Directly averaging them makes the result depend on model-specific score
scales. RRF combines rank positions instead, keeping the fusion boundary
stable when the embedding model changes.

The cost is that RRF discards absolute score distance and introduces a rank
constant and candidate-pool size that must be recorded and evaluated. The
implemented adapter includes those values and both child algorithm identities
in its own algorithm digest.

## Fail-closed implementation

`workers/memory-rag/src/egopulse_memory_rag/experimental.py` provides:

- `EmbeddingProfile`, requiring provider, model, immutable revision and vector
  dimensions before an experiment can run;
- `ExactVectorRetriever`, rejecting provider failure, output-count drift,
  dimension drift, non-numeric/non-finite values and zero vectors;
- `ReciprocalRankFusionRetriever`, rejecting child algorithm/query identity
  drift, duplicate or unknown references, source/content digest drift,
  missing evidence, score-range violations and candidate-pool overflow;
- deterministic tie-breaking by Memory ID and evidence digests that include
  the algorithm configuration and ranked references;
- no persistence, network, SQLCipher, Authority mutation or daemon contract
  change.

The lexical implementation now reuses `validate_retrieval_input`; all current
and future algorithms therefore share the same record-count, content-size,
state, digest, scope and duplicate-ID checks.

## Conformance evidence

The local Python suite records 38 passing tests, including:

- a paraphrase recovered by an injected deterministic fixture vector;
- lexical plus semantic RRF ordering and evidence stability;
- Phase 2-12 evaluator acceptance of exact-vector and hybrid callables;
- fail-closed tests for vector count, dimensions, non-finite values and zero
  magnitude;
- rejection of a child retriever that tampers with a source reference.

Fixture vectors prove adapter conformance only. They are deliberately not
reported as model-quality evidence and cannot authorize production semantic
retrieval.

## Technology decision still open

No local embedding model or cached model artifact is currently available in
the development environment. Selecting one now without a representative
English/Chinese corpus, immutable model revision, package footprint, CPU
latency and redistribution-license evidence would confuse a technology guess
with an architecture decision.

The next gate must therefore:

1. build a versioned, non-sensitive project-derived evaluation corpus with
   difficult lexical and semantic negatives;
2. evaluate at least two multilingual embedding candidates through the exact
   adapter, recording model revision, dimensions, package size, cold start,
   per-case latency and quality metrics;
3. compare lexical, semantic and RRF hybrid results on the same dataset digest;
4. evaluate reranking only if first-stage recall is adequate but ordering is
   still materially deficient;
5. present the measured trade-off for Founder admission before changing the
   production profile or packaging a model.

Until that gate is closed, the production fallback and frozen wire contract do
not change.
