# EgoPulse agent instructions

## Scope

This repository contains product implementation. Historical research and governance automation stay outside this repository unless an approved migration work package explicitly imports them.

## Required behavior

- Preserve Authority ownership and dependency direction in `ARCHITECTURE.md`.
- Do not let UI, TypeScript Harnesses or Python Workers write authority state.
- Add contracts before cross-language implementation.
- Keep external side effects behind adapters and make retries idempotent.
- Add tests proportional to changes and report what was not verified.
- Do not claim a scaffold, stub or passing unit test is a completed product capability.

## Commands

```text
pnpm run check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
uv run --project workers/foundation-probe --frozen pytest workers/foundation-probe --rootdir workers/foundation-probe
```
