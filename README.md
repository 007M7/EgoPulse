# EgoPulse

EgoPulse is the clean implementation repository for the Founder-controlled Personal Agent OS.

The repository starts from the frozen architecture and technology baseline. It does not copy the historical governance runtime; each implemented vertical is carried by its own contracts, persistence boundaries, tests and release evidence.

## Foundation status

Current maturity: **Gate 4 vertical implementation in progress — V-01/C5 CLI+TUI closed, typed production bootstrap wired, Sego/second Harness pending**.

Available now:

- Rust workspace for deterministic authorities, collaboration control, daemon, CLI and TUI;
- V-01 governed single-Harness control path: Task activation → Collaboration commit → Adapter dispatch → activation acknowledgement;
- Codex App Server adapter with durable Adapter Edge and an explicit `CodexHarnessCompositionConfig` composition root;
- C5 real Windows local-IPC E2E coverage for daemon, CLI and TUI (serial fixture run: 6/6 passed);
- user-owned production bootstrap JSON with environment-resolved secret keys and fail-closed validation;
- Tauri 2 + React + TypeScript desktop shell;
- TypeScript packages for generated clients, Agent SDK and the bounded native Harness;
- isolated CPython 3.14 Worker project managed by uv;
- Protobuf/Buf and JSON Schema contract roots;
- local CI, repository-boundary checks and commit-bound release-candidate packaging.
- account-authenticated Windows Named Pipe / Unix Domain Socket transport and an ephemeral, policy-resolved local session service.

Not implemented yet:

- second Harness adapter and multi-model collaboration path (Kimi CLI / DeepSeek Harness are next Phase 2-03 candidates);
- production Memory/RAG authority and its cross-language contract (a read-only
  lexical retrieval candidate worker now exists under `workers/memory-rag`);
- SQLCipher-backed Memory/RAG indexes and retrieval evaluation;
- Sego verification integration;
- production packaging or release.

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
  local-api/          local API client/server gateway boundary
  local-ipc-platform/ OS peer identity and owner-only local transport
  process-supervision/process and Attempt supervision primitives
packages/
  generated-client/  generated TypeScript contract target
  agent-sdk/          AgentOS-native SDK boundary
  native-harness/     bounded Layer 4 LangGraph.js Harness
workers/
  foundation-probe/  isolated Python Worker pattern
  memory-rag/        read-only deterministic retrieval candidate
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

For the current delivery controls, install the tracked fast pre-push hook with
`scripts/install-git-hooks.ps1`. Pull requests and release tags use the
GitHub Actions CI/CD workflow; use `pnpm run ci:local` or `pnpm run cd:local`
only for offline reproduction. See [Local CI/CD](docs/engineering/local-ci-cd.md),
[Foundation Gate](docs/foundation-gate.md) and [Architecture](ARCHITECTURE.md).
