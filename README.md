# EgoPulse

EgoPulse is the clean implementation repository for the Founder-controlled Personal Agent OS.

The repository starts from the frozen architecture and technology baseline. It does not copy the historical governance runtime; each implemented vertical is carried by its own contracts, persistence boundaries, tests and release evidence.

## Foundation status

Current maturity: **phase-one Windows x64 CLI/TUI release-candidate preparation — the governed V-01 loop, immutable per-work capability routing, governed Memory context consumption, Sego verification and shared natural-language Work Start flow are implemented; Desktop remains outside this package**.

Available now:

- Rust workspace for deterministic authorities, collaboration control, daemon, CLI and TUI;
- V-01 governed single-Harness control path: Task activation → Collaboration commit → Adapter dispatch → activation acknowledgement;
- Codex App Server adapter with durable Adapter Edge and an explicit `CodexHarnessCompositionConfig` composition root;
- C5 real Windows local-IPC E2E coverage for daemon, CLI and TUI;
- user-owned production bootstrap JSON with environment-resolved secret keys and fail-closed validation;
- Tauri 2 + React + TypeScript Desktop shell attached to the same authenticated local API and Rust Client Kernel as CLI/TUI, including governed Task cancellation, Memory governance and accepted-snapshot retrieval;
- TypeScript packages for generated clients, Agent SDK and the bounded native Harness;
- isolated CPython 3.14 Worker projects managed by uv;
- internal Rust Memory Authority with SQLCipher persistence, candidate-only agent writes, Founder promotion/revocation and accepted retrieval snapshots;
- governed `LocalCognitionService/RetrieveMemory` exposed consistently through CLI, TUI and Desktop, with daemon-owned scope authorization, supervised Python retrieval, typed failure semantics and reference-only output;
- governed future-work defaults and immutable per-work Provider/Harness/model route selection shared by CLI and TUI;
- a cross-Harness composition proof showing one exact GPT model can be represented and composed through Codex and DSH driver implementations while unproven routes remain non-selectable;
- offline Memory retrieval evaluation with dataset-digest evidence, Recall/MRR/nDCG metrics, injected exact-vector scoring and validated RRF experiment adapters;
- explicit Sego/checker verification composition with owner-backed Artifact reads, supervised execution, immutable verification artifacts and Task write-back;
- Protobuf/Buf and JSON Schema contract roots;
- local CI, repository-boundary checks and commit-bound unsigned Windows early-access packaging;
- commit-bound Windows x64 CLI/TUI packaging, one-click installation checks and archive/per-file SHA-256 verification; candidate-specific evidence is recorded under `docs/release/`;
- account-authenticated Windows Named Pipe / Unix Domain Socket transport and an ephemeral, policy-resolved local session service.

For the current Windows x64 package path, see [Windows early access](WINDOWS-EARLY-ACCESS.md).

Not admitted or not yet closed:

- native Desktop GUI automation and the remaining end-to-end Desktop workflows (the shared-kernel read, TaskCreate, Task cancellation, Approval and Memory mutation paths are locally verified);
- authenticated production admission for DeepSeek/DSH, Kimi and GLM/OpenCode; this is a post-release promotion gate, not a blocker for the first Codex-backed CLI/TUI package;
- production semantic/vector retrieval and reranking; exact-vector and RRF plumbing exists only behind the offline experiment gate, while the release baseline remains deterministic lexical retrieval;
- signed production release and SmartScreen reputation; the current package is
  explicitly unsigned and must be treated as early access.

## Repository map

```text
apps/
  agentosd/          Rust deployment host
  cli/               scriptable Rust client
  tui/               Rust terminal surface
  desktop/           Tauri 2 + React + TypeScript surface
crates/
  domain-contracts/  domain-facing Rust types only
  cognition-runtime/ authority boundary skeletons
  local-ide-control/ deterministic collaboration control skeletons
  local-api/         local API client/server gateway boundary
  local-ipc-platform/ OS peer identity and owner-only local transport
  process-supervision/ process and Attempt supervision primitives
packages/
  generated-client/  generated TypeScript contract target
  agent-sdk/         AgentOS-native SDK boundary
  native-harness/    bounded Layer 4 LangGraph.js Harness
workers/
  foundation-probe/ isolated Python Worker pattern
  memory-rag/        supervised read-only deterministic retrieval Worker
contracts/
  proto/             internal Protobuf source
  json-schema/       Artifact and tool schemas
docs/
  decisions/         repository-local implementation ADRs
```

## Prerequisites

- Rust 1.98.0 via rustup (pinned by `rust-toolchain.toml`)
- Node.js 24 LTS
- pnpm 11
- CPython 3.14
- uv

## Verify

```powershell
pnpm install --frozen-lockfile
pnpm run check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
uv sync --project workers/foundation-probe --frozen
uv run --project workers/foundation-probe --frozen pytest workers/foundation-probe --rootdir workers/foundation-probe
```

For the current delivery controls, install the tracked fast pre-push hook with `scripts/install-git-hooks.ps1`. GitHub Actions CI/CD remains configured for pull requests and release tags, but the current development gate uses local CI/CD because the Actions usage quota is exhausted; remote failures are non-blocking until capacity returns. See [Local CI/CD](docs/engineering/local-ci-cd.md), [Foundation Gate](docs/foundation-gate.md) and [Architecture](ARCHITECTURE.md).
