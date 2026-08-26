# Phase 2-37: Current implementation and admission status

- Status: Gate 4 implementation continues; V-01 CLI/TUI delivery path is locally releasable as unsigned early access
- Evidence date: 2026-08-27
- Decision owner: Founder

## Purpose

This is the current single status record for the implementation repository. It
separates three facts that must not be conflated:

1. a boundary can be implemented and locally tested;
2. a provider can be composed behind that boundary;
3. a capability can be admitted into the first user release.

The second fact never implies the third without provider-specific evidence.

## Current closure matrix

| Area | Current fact | Release disposition |
| --- | --- | --- |
| F0 foundation | Independent repository, contract roots, Rust/TypeScript/Python checks and local delivery controls are established | Closed |
| V-01 / C5 | One governed Codex work loop is exercised through real Windows local IPC; CLI and TUI use the same client kernel and authority path | Closed for CLI/TUI |
| G4 authorities | Task, Collaboration, Adapter, Artifact, Verification and Founder-Verdict slices have owner-backed local implementations and targeted evidence | Closed for the admitted V-01 slice; physical power-loss qualification and signing remain release obligations |
| Memory Authority | Rust SQLCipher single writer; Agent/Model/Harness input is candidate-only; Founder acceptance and governance revocation are explicit | Closed for initial governance boundary |
| Memory mutation path | CLI/TUI mutation RPC and fixed internal producer handles are implemented; a real Codex app-server candidate handoff reaches the Rust Authority in a cross-component test | Closed as candidate-only handoff; ordinary terminal output is not auto-promoted to Memory |
| Memory retrieval | Python Worker reads only accepted, scoped snapshots and returns reference-only lexical-overlap-v0 results | Production baseline |
| Semantic RAG | Exact-vector/RRF experiment adapters exist; E5-small is the measured candidate, but package and runtime costs require an explicit Founder admission decision | Not admitted by default |
| Multi-model composition | Exact profile routing and isolated per-provider Collaboration/Adapter stores support heterogeneous drivers under one scheduler | Boundary closed; provider admission remains independent |
| Codex | Real authenticated app-server lifecycle, governed approval/recovery/return path and current candidate package are verified locally | Active production Harness |
| Kimi | ACP initialize probe reaches authentication-required in an isolated process; authenticated prompt/approval/recovery/return evidence is absent | Candidate-only / held |
| DSH | Fresh-session replay, cancellation and permission path are locally evidenced; native load/resume and independently attested Artifact semantics are absent | Candidate-only / held |
| Desktop | Tauri 2 + TypeScript shell exists and shares the intended kernel boundary, but Desktop product capability/distribution is explicitly deferred | Phase four, not first release |
| Windows package | CLI/TUI/agentosd package contains 52 hashed files and passes local package verification; no signing certificate exists | Unsigned early-access candidate |

## Current release candidate

The packaged binaries are bound to the exact code commit below. Later commits
that change documentation only do not change this binary candidate.

```text
code commit: ffb699477f3aac3de8cf04778480274bdccf23e2
platform: windows-x86_64
surfaces: cli, tui
archive: .artifacts/release-candidate/egopulse-0.1.0-ffb699477f3a-windows-x86_64-20260826T232149Z.zip
archive SHA-256: 6352735659755b5fdc8cc202a3fef8909fd002fe110da9bbbad6d0da9013e3d1
```

The matching local CI evidence passed all eight stages with a clean worktree.
The package verifier passed all 52 file hashes, CLI/TUI/agentosd help probes,
Memory Worker setup and the production-profile no-`fastembed` check.

The current implementation was rechecked on Windows x64 after this status
record was prepared:

```text
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture -- --test-threads=1 --nocapture
8 passed, 0 failed

EGOPULSE_CODEX_EXECUTABLE=<installed Codex app-server>
cargo test -p egopulse-agentosd --test codex_memory_candidate_e2e -- --nocapture
1 passed, 0 failed
```

The first command covers real local IPC, shared CLI/TUI operations, governed
Memory retrieval and governed Memory mutation. The second covers a real
authenticated Codex app-server response entering the Rust Memory Authority
only through the explicit fixed Harness producer handle, followed by Founder
acceptance. Running the second command inside the restricted tool sandbox
produced `CODEX_APP_SERVER_EOF` because the child could not access the user
Codex runtime directory; the complete-permission rerun passed and is the
authoritative result.

## Explicitly remaining admission work

### 1. Semantic RAG decision

The experiment result is sufficient to make a decision, not to make one
silently. The current evidence records E5-small as the best measured candidate
on the available corpus, with a roughly 487 MiB model snapshot and roughly
956 MiB measured peak working set. It also records preprocessing, packaging,
update, cold-start and offline-distribution costs.

The two valid choices are:

- admit E5-small as an opt-in local semantic profile, with its model artifact,
  dependency, package verification and fallback behavior explicitly versioned;
- keep lexical-overlap-v0 as the first-release retrieval profile and continue
  semantic evaluation outside the production package.

Until Founder selects one, no semantic model is downloaded, bundled, or
advertised as a production capability. In either choice, the Rust Memory
Authority, accepted-snapshot boundary, Python read-only rule and reference-only
result contract remain unchanged.

### 2. Second Harness admission

The multi-model control-plane work is not blocked by the absence of a second
admitted provider: the scheduler, exact profile routing and per-provider state
isolation are already implemented. Admission is held because a second
provider must independently prove authenticated lifecycle, structured
approval, cancellation, restart/reconciliation and technical return evidence.

Kimi currently fails at the authenticated boundary with
`authentication_required`. DSH has useful local replay evidence but its native
resume/load and Artifact semantics are unsupported or unverified. Neither
provider is therefore selected by production configuration.

## Next implementation order

1. Record the Founder decision for semantic retrieval and implement only the
   selected profile's packaging/configuration/evidence path.
2. Keep Codex as the sole admitted production Harness while running any Kimi or
   DSH probes as isolated candidate evidence.
3. Keep the production Memory candidate bridge as an explicit,
   user-reviewed proposal operation. It must not turn every terminal transcript
   into a memory, must preserve the Artifact return path, and must use the
   fixed producer binding already implemented. The current real Codex E2E is
   the cross-component proof; CLI/TUI already expose the corresponding
   user-reviewed `memory candidate` operation through the Local API. A future
   terminal-output inbox may improve ergonomics, but it is not required for the
   first release and must not bypass Founder acceptance.
4. After the chosen Memory profile and product-facing candidate bridge are
   evidenced, refresh the CLI/TUI early-access package. The current package was
   refreshed for the fixed producer-proposal boundary; Desktop remains a later
   vertical.

## Non-claims

This status does not claim semantic/vector retrieval in the first package,
automatic transcript learning, authenticated Kimi/DSH production support,
Desktop distribution, signed Windows binaries, cloud telemetry, enterprise
identity, or server-scale capacity.
