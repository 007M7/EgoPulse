# EgoPulse six-stage delivery baseline

- Date: 2026-08-27
- Repository: `007M7/EgoPulse`
- Decision owner: Founder
- Classification: implementation roadmap and evidence index
- Status: stages one through four and the phase-one CLI/TUI slice are
  implemented; refreshed Windows candidate verification is pending

This document translates the frozen architecture into a delivery sequence.
It is not a new architecture decision and it does not promote a candidate
Provider, Harness, model or Memory algorithm. A stage is closed only when its
exit evidence proves the product behavior at the same boundary as the claim.

## Product end state

EgoPulse is a local Founder-controlled Agent OS. CLI, TUI and Desktop are
different surfaces over one shared Rust client kernel and one local governed
control plane. The control plane coordinates Tasks, Policy, Collaboration,
Memory, Artifacts, Verification, Founder Verdicts and process recovery. It
can compose multiple Provider/Model/Harness routes, but each route remains
bound to an exact model, an independently attested capability profile and an
isolated evidence path.

The cognition plane supplies replaceable Python Workers for parsing,
embedding, reranking, retrieval and evaluation. Workers never own Task or
Memory facts. Agent/Model/Harness output can propose a Memory candidate; only
the Rust Memory Authority and an authorized Founder/governance action can
make it accepted or revoked.

The first release is local BYOK Windows x64 software. It does not claim cloud
telemetry, enterprise identity, server-scale capacity or signed binaries when
those facilities are not present.

## Six-stage sequence

### Stage 1 — independent foundation and contracts

Purpose: establish a buildable implementation repository and stable machine
boundaries before product behavior is added.

Scope:

- independent `EgoPulse` repository and public/private content boundary;
- Rust workspace and authority-facing crate boundaries;
- TypeScript package and generated-client boundary;
- isolated Python Worker projects managed by `uv`;
- Protobuf/Buf and JSON Schema contract roots;
- cross-language generated bindings;
- local fast check, local full CI and Windows local CD.

Exit evidence:

- locked dependency installation;
- Rust format/lint/build/test evidence;
- TypeScript/contracts and Desktop frontend checks;
- Python lock/test evidence;
- Buf and JSON Schema checks;
- boundary and clean-worktree checks;
- a reproducible local package path.

Current disposition: **closed as F0**. The authoritative record is
`docs/foundation-gate.md` and the current local CI/CD policy is in
`docs/engineering/local-ci-cd.md`.

### Stage 2 — deterministic control plane and first governed vertical

Purpose: make one complete Agent work loop correct before adding provider
breadth.

Scope:

- Task Authority and transition guards;
- Policy and approval decisions;
- Collaboration Control and activation leases;
- Adapter Edge and terminal observation intake;
- Artifact Authority and content-addressed bytes;
- Sego/Checker verification;
- Founder Verdict issue, consume, apply and revoke;
- process supervision and fail-closed recovery;
- account-authenticated local IPC;
- shared Rust Client Kernel;
- CLI/TUI operations over the real local daemon.

Exit evidence:

```text
real Windows IPC
  -> authenticated session
  -> task activation
  -> governed Harness dispatch
  -> terminal observation
  -> artifact/evidence
  -> verification
  -> Founder verdict
  -> projected CLI/TUI result
```

Current disposition: **closed for V-01 CLI/TUI with Codex as the admitted
production Harness**. C5 fixtures and the V-01 evidence documents are the
authoritative runtime evidence. This stage does not imply that other
Providers are admitted.

### Stage 3 — Provider, Harness and Model composition

Purpose: turn the provider-neutral composition boundary into an actually
usable, exact and independently admitted multi-model capability.

Scope:

- Provider profile, Harness identity and model identity remain separate;
- redacted model catalog snapshots with source and digest provenance;
- exact model selection and dispatch receipt matching;
- user-visible provider/model readiness and selection;
- Codex, DeepSeek/DSH, Kimi and GLM/OpenCode adapter lifecycle checks;
- authentication, prompt, approval, cancellation, restart/recovery and
  technical return evidence per Provider;
- per-provider Collaboration/Adapter storage isolation;
- deterministic multi-model task routing and explicit no-route behavior;
- candidate, held and production admission states.

Non-negotiable exit conditions:

1. a passing adapter compile or catalog listing is not admission evidence;
2. every admitted route has a real authenticated exact-model lifecycle;
3. silent model substitution is rejected;
4. missing, ambiguous or stale provider routes fail closed;
5. approval, cancellation, recovery and Artifact return semantics are
   evidenced separately from a fresh prompt;
6. one provider's state cannot write another provider's authority store.

Current disposition: **phase-one composition and governed selection are
closed; additional production admissions are deferred**. Codex is active.
Provider, Harness and exact model are independently represented, one synthetic
GPT model is composed through Codex and DSH driver implementations, and the
shared CLI/TUI work-capability surface resolves immutable routes. DSH, Kimi
and GLM/OpenCode remain candidate/held routes. Their real authentication is a
post-release promotion gate rather than a blocker for the first Codex-backed
package.

### Stage 4 — Memory Authority and production RAG

Purpose: provide useful long-term context without allowing an Agent, model or
Worker to become the source of truth.

Scope:

- Rust SQLCipher Memory Authority;
- candidate, accepted and revoked lifecycle;
- Founder/governance acceptance and revocation;
- revision, idempotency, scope and audit invariants;
- accepted-snapshot export to a supervised read-only Python Worker;
- lexical baseline retrieval;
- semantic/vector and hybrid experiments behind replaceable adapters;
- representative project corpus and Recall/MRR/NDCG evaluation;
- artifact/model/snapshot provenance;
- opt-in admission and fixed lexical rollback;
- product-facing candidate proposal flow that never auto-accepts output.

Non-negotiable exit conditions:

```text
Worker result
  -> reference-only response
  -> snapshot/digest validation
  -> Rust Authority remains sole writer
  -> Founder acceptance required for fact promotion
```

Current disposition: **governance boundary, lexical production baseline and
governed work-context consumption are closed; semantic RAG admission remains
optional and incomplete**. M-01 through M-13 and the current
evaluation gate are locally verified. M-12 proves that accepted and revoked
Memory facts, read-only lexical retrieval and exact revoke replay survive a
graceful C5 fixture-daemon restart with the same DataRoot and IPC instance; it
does not claim packaged-install, hard-kill or Provider recovery. The detailed
evidence is recorded in
`phase-2-57-memory-daemon-restart-evidence-20260902.md`. The first real
semantic/hybrid candidate was evaluated and rejected for Recall/NDCG
regression; a semantic candidate may become opt-in only after a passing
evaluation, Founder selection of the profile, and acceptance of
package/runtime costs, provenance and rollback behavior.

### Stage 5 — complete product surfaces

Purpose: expose the same governed capability consistently to users.

Scope:

- CLI completion for task, provider/model, approval, evidence, Memory and
  recovery operations;
- TUI completion for live task state, approval queues, evidence graphs,
  Memory candidate review and model routing;
- Desktop completion using Tauri 2, React and TypeScript over the same local
  API and shared Rust kernel;
- first-run configuration and one-click Windows setup;
- safe display of provider readiness without secrets;
- shared error, permission, loading, reconnect and stale-projection
  semantics across surfaces;
- offline/local-only operation and user-owned API keys.

Exit evidence:

- the same operation produces equivalent authority facts on all included
  surfaces;
- CLI and TUI remain usable without Desktop;
- Desktop adds presentation, not a second control plane;
- reconnect, daemon restart and denied authorization are tested on each
  included surface;
- a clean Windows x64 package can be installed and used by a new user.

Current disposition: **CLI/TUI first-release implementation and refreshed
Windows x64 package acceptance are closed at commit `5c8a1e8`**. Desktop
shared-kernel code remains in the repository, but native GUI acceptance and
distribution are intentionally outside phase one. The included surfaces use
the same Rust client kernel and daemon semantics.

### Stage 6 — release, maintenance and governed evolution

Purpose: make the product distributable and able to improve without silently
changing Founder-controlled behavior.

Scope:

- Windows x64 release candidate and package verifier;
- per-file and archive SHA-256 evidence;
- unsigned early-access distribution until a signing certificate exists;
- SmartScreen risk disclosure;
- local CI/CD as the current operational gate, with remote workflow kept
  reproducible;
- versioned migration and rollback policy;
- compatibility checks for contracts, providers, model catalogs and Workers;
- RSI research/evaluation plane that produces candidates only;
- Founder activation, staged rollout and rollback of accepted candidates;
- issue, failure, recovery and release evidence retained with the package.

Exit evidence:

- a fresh machine can install and run the declared release surfaces;
- the package verifier proves the exact archive contents and startup probes;
- release metadata states signed or unsigned status truthfully;
- no research candidate changes production routing or Memory facts without
  an explicit governed activation;
- the release can return to the last accepted profile without data loss.

Current disposition: **unsigned CLI/TUI early-access candidate verified at
commit `5c8a1e8`; the package contains 55 files and passes package, startup,
installer and Memory Worker checks. Desktop remains a separately buildable
shared-kernel candidate and is not included until native GUI acceptance is
closed. Public GitHub Release publication and the governed evolution loop
remain pending**. The reproducible evidence, exact archive name and SHA-256 are
recorded in `docs/release/windows-candidate-20260905.md`.

## Current next actions

The phase-one clean-CI, Windows package and evidence sequence is closed.
Remaining work is deliberately outside this candidate gate:

1. publish the verified archive only after explicit GitHub Release approval,
   preserving the recorded SHA-256 beside the download;
2. after phase one, run real authenticated lifecycle probes before promoting
   DeepSeek, Kimi, GLM or another Harness route;
3. evaluate semantic/hybrid Memory candidates without replacing the admitted
   lexical rollback profile; and
4. resume Desktop as a later presentation surface over the same kernel.

## Evidence rule

The following distinctions are required in every future status report:

| Statement | What proves it |
|---|---|
| boundary exists | typed implementation and targeted contract tests |
| route composes | real composition test with isolated stores and exact profile |
| provider is reachable | authenticated exact-model lifecycle evidence |
| provider is admitted | lifecycle plus approval, recovery and Artifact evidence |
| Memory algorithm is eligible | identical corpus, metrics, replay and provenance gate |
| capability is released | package verifier and fresh-install evidence |

No lower row may be inferred from a higher row.
