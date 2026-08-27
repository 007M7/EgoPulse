# Phase 2-39: Configuration preflight and current candidate refresh

- Status: locally verified; unsigned early-access candidate refreshed and package setup hardened
- Evidence date: 2026-08-27
- Decision owner: Founder

## Purpose

The first release needs a low-cost way to distinguish malformed local
configuration from store, IPC or provider-runtime failures. This slice adds a
non-invasive daemon preflight and binds the refreshed Windows x64 candidate to
the same commit that contains it.

## Configuration preflight contract

```text
agentosd --check-config
        |
        +-- parse DaemonConfig from environment
        +-- parse ProductionBootstrapConfig and user-owned JSON
    +-- validate identities, paths, required read-model/token keys and daemon settings
        +-- do not open Authority stores
        +-- do not create business databases
        +-- do not bind local IPC
```

Successful validation prints:

```text
agentosd configuration=passed stores_opened=false
```

Invalid, missing or out-of-range configuration is refused with exit code
`78`. The real binary tests confirm that rejected checks do not create the
configured user-owned file or open the stores. This is a diagnostic boundary
only; it does not accept memory candidates, start a Harness, or modify
configuration.

## Evidence

```text
cargo fmt --all -- --check                         passed
cargo clippy -p egopulse-agentosd --all-targets -- -D warnings  passed
cargo test -p egopulse-agentosd --test config_check -- --nocapture  3 passed
pnpm run ci:local                                  8/8 stages passed
```

The full local CI evidence is bound to commit
`294fe9bb712d8079503899513f91910f059f5f71` and started from a clean
worktree. GitHub Actions is informational while the repository's Actions
quota is exhausted; Windows local CI/CD remains the operational authority.

## Refreshed candidate

```text
classification: unsigned-release-candidate
commit: 294fe9bb712d8079503899513f91910f059f5f71
archive: .artifacts/release-candidate/egopulse-0.1.0-294fe9bb712d-windows-x86_64-20260827T003543Z.zip
archive SHA-256: 006a0af71a912b83b3c5bdce3fe31e5e60015a334e5a7527a7ec1f7ffa41f2ba
package files: 52
package verifier: passed
independent short-path extract audit: passed
```

The candidate contains CLI, TUI and `agentosd`; CLI and TUI continue to share
the Rust kernel and governed Local API. No signing certificate is available,
so this remains an unsigned early-access package and must carry the expected
Windows SmartScreen warning. Its packaged Memory Worker setup uses a writable
package-local `.cache/uv` directory by default.

## Boundary and remaining decisions

The preflight reduces configuration failure cost but does not change the
frozen architecture or admission policy. Lexical-overlap-v0 remains the
production retrieval baseline until Founder explicitly admits semantic RAG.
Codex remains the sole admitted production Harness; Kimi and DSH remain
candidate-only pending their independent lifecycle and return-path evidence.
