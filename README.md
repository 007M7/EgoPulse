# EgoPulse

EgoPulse is the clean implementation repository for the Founder-controlled Personal Agent OS.

The repository starts from the frozen architecture and technology baseline, but it does not copy the historical governance runtime or claim that product capabilities already exist.

## Foundation status

Current maturity: **foundation scaffold**.

Available now:

- Rust workspace for deterministic authorities, collaboration control, daemon, CLI and TUI;
- Tauri 2 + React + TypeScript desktop shell;
- TypeScript packages for generated clients, Agent SDK and the bounded native Harness;
- isolated CPython 3.14 Worker project managed by uv;
- Protobuf/Buf and JSON Schema contract roots;
- local CI, repository-boundary checks and commit-bound release-candidate packaging.

Not implemented yet:

- Task, Memory, Policy, Verdict or Release authority behavior;
- local IPC transport;
- SQLCipher persistence or Qdrant indexing;
- Codex, Kimi or DeepSeek Harness adapters;
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
  local-api/          local API client boundary
  process-supervision/process and Attempt supervision primitives
packages/
  generated-client/  generated TypeScript contract target
  agent-sdk/          AgentOS-native SDK boundary
  native-harness/     bounded Layer 4 LangGraph.js Harness
workers/
  foundation-probe/  isolated Python Worker pattern
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

For the current delivery controls, install the tracked pre-push hook with
`scripts/install-git-hooks.ps1`, then use `pnpm run ci:local` and
`pnpm run cd:local`. See [Local CI/CD](docs/engineering/local-ci-cd.md),
[Foundation Gate](docs/foundation-gate.md) and [Architecture](ARCHITECTURE.md).
