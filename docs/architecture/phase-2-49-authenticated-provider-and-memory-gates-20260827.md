# Phase 2-49 authenticated Provider admission and Memory/RAG candidate gate

- Date: 2026-08-27
- Scope: DeepSeek Harness, Kimi CLI, GLM/OpenCode, and read-only Memory/RAG
- Status: implementation complete; real Provider admission remains evidence-gated
- Default behavior: Codex remains the only production Harness; lexical retrieval remains the default

## Provider lifecycle entry

Each candidate adapter now has an ignored integration test named
`authenticated_*_exact_model_terminal_lifecycle`. The test sends exactly one
explicitly authorized, no-tool prompt from an isolated temporary workspace and
records only provider, exact model, terminal status, and output byte count. It
does not print API keys or model output.

The test refuses to run unless both `EGOPULSE_ALLOW_PROVIDER_INFERENCE=1` and
`EGOPULSE_PROVIDER_AUTH_READY=1` are present. It also requires a provider-owned
executable and an exact model ID. The adapter itself rejects an ACP session
whose returned model does not equal that ID; there is no fallback route.

The common Windows entry point is:

```powershell
$env:EGOPULSE_PROVIDER_AUTH_READY = '1'
./scripts/probe-provider-authenticated-windows.ps1 `
  -Provider kimi `
  -ExecutablePath 'C:\Users\Administrator\AppData\Roaming\npm\kimi.cmd' `
  -ExactModel 'kimi-k2.5' `
  -AllowInference
```

Use the equivalent provider values `deepseek` and `glm` for the other two
candidates. This command is an evidence probe, not a production promotion
command. A passing prompt and terminal event proves only the fresh
authenticated lifecycle slice; approval, Artifact/Verification settlement,
and restart reconciliation remain separate admission rows. In particular,
DSH and OpenCode still report native recovery as unattested until their native
load/resume behavior is independently proven.

## Memory/RAG production gate

`egopulse_memory_rag.admission.evaluate_candidate_gate` consumes a lexical
baseline report and a semantic/hybrid candidate package. It fails closed when
any of these facts is absent or invalid:

1. identical dataset ID, canonical dataset SHA-256, case count, and `k`;
2. candidate recall, MRR, and NDCG no lower than the baseline;
3. deterministic replay attestation;
4. model artifact digest, snapshot revision, and positive artifact sizes;
5. initialization/evaluation timing and configured resource budgets.

On every result it emits the fixed rollback target
`lexical-overlap-v0` and `default_route_changed=false`. A pass means only
`eligible_for_opt_in=true`; it does not change the default Worker selection,
Memory Authority, or Rust contracts. A failed candidate can therefore be
discarded and the runtime remains on the lexical route without a data migration.

The full model evaluation command is:

```powershell
./scripts/evaluate-memory-gate.ps1 `
  -DatasetPath 'workers\memory-rag\evaluation\project-boundaries-v0.json' `
  -Model multilingual-e5-small-v0 `
  -OutputPath '.artifacts\memory-rag\evaluation-gate.json'
```

The script is local-files-only unless `-AllowDownload` is explicitly supplied.
No model cache or embedding index is a Memory source of truth; the Rust
Authority continues to own accepted/revoked state and the Python Worker only
reads a bounded accepted snapshot.

## Evidence status in this environment

- Python Memory/RAG test suite: 45 passed, including gate pass, metric
  regression rejection, missing provenance rejection, and rollback assertions.
- The real local semantic candidate run for `multilingual-e5-small-v0` was
  executed on the fixed project corpus and rejected by the quality gate:
  Recall@2 regressed from `1.0` to `0.92857143` and NDCG@2 regressed from
  `0.8681892` to `0.84948495`. The detailed evidence is in
  `phase-2-52-semantic-rag-candidate-evaluation-20260827.md`.
- Rust DSH/Kimi/OpenCode adapter tests compile, including all three ignored
  authenticated lifecycle entry points.
- No real Provider prompt was sent in this implementation run: the current
  environment has no user credential readiness flag and OpenCode is not
  installed. Therefore no candidate is promoted by this phase.
