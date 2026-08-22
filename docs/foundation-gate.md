# Foundation Gate F0

- Status: passed
- Date: 2026-08-22
- Owner: Founder
- Repository: `007M7/EgoPulse`

## Purpose

Establish an independent, buildable implementation repository before any business vertical unit begins.

## Acceptance criteria

- [x] The remote repository is independent and contains no inherited history.
- [x] Product implementation and historical governance responsibilities are documented separately.
- [x] Rust workspace formats, lints, builds and tests.
- [x] Desktop and TypeScript packages install from a lockfile, typecheck and build.
- [x] Python Worker syncs from a lockfile and tests under CPython 3.14.
- [x] Protobuf passes Buf lint and JSON Schema fixtures pass repository checks.
- [x] CI reproduces the same checks without secrets.
- [x] Initial commit is pushed to the private remote.

## Non-goals

- No business feature or real Authority state machine.
- No migration of old Python/Electron runtime code.
- No SQLCipher/Qdrant service startup.
- No Harness or Sego integration.
- No installer, release or production readiness claim.

## Local evidence

Verified on Windows x86_64 on 2026-08-22:

- `pnpm install --frozen-lockfile`
- `pnpm run check`
- `pnpm --filter @egopulse/desktop run build`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `uv sync --project workers/foundation-probe --frozen`
- `uv run --project workers/foundation-probe --frozen pytest workers/foundation-probe --rootdir workers/foundation-probe`
- CLI, TUI and `agentosd` probes all returned the explicit `foundation-only` state.

## Remote evidence

- Initial foundation commit: `cce6c230c02f6f877a4b1dfe42008822be7ab206`
- GitHub Actions run: [foundation 32555457932](https://github.com/007M7/EgoPulse/actions/runs/32555457932)
- Successful jobs: `rust`, `typescript-and-contracts`, `python`

## Exit

Foundation F0 is closed. EgoPulse may now select its first business vertical unit, but F0 does not
claim that any AgentOS product capability is implemented.
