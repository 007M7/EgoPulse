# Windows x64 early-access candidate evidence

- Date: 2026-08-27
- Repository: `007M7/EgoPulse`
- Commit: `38d665b68a35d8d736e70beb20495c78bd7d1b3c`
- Classification: `unsigned-release-candidate`
- Included surfaces: CLI and TUI, backed by `agentosd` and the shared Rust Client Kernel

## Local CI evidence

The full local CI gate passed from a clean worktree at the exact candidate
commit. All eight stages passed in `67,671 ms`. The machine-readable source is
`.local-ci/evidence/latest.json`; that path is ignored by Git and the package
contains a copy at `manifests/local-ci-evidence.json`.

## Package evidence

- Archive: `egopulse-0.1.0-38d665b68a35-windows-x86_64-20260827T142127Z.zip`
- Archive SHA-256:
  `0733c03a3613893af24faa12bc78b158a66eb57d76fc8d88913e7c108fa0d936`
- Package verification: passed, `files=55`
- CLI, TUI and daemon `--help`: passed
- TUI non-interactive foundation probe: passed
- daemon missing-configuration fail-closed probe: passed
- isolated Memory Worker setup: passed
- locked production Memory Worker profile: passed

The package is usable for local CLI/TUI testing after the user supplies the
required local configuration and Provider credentials. It is unsigned, so
Windows SmartScreen may show an unknown-publisher warning.

## Distribution boundary

This evidence authorizes local/manual early-access testing of the CLI/TUI
slice. It does not claim:

- a signed binary or SmartScreen reputation;
- authenticated production admission for DeepSeek, Kimi or GLM/OpenCode;
- semantic/vector RAG production admission;
- native Desktop GUI acceptance or Desktop distribution;
- final release approval or automatic model substitution.

Users must verify the published ZIP hash and read `WINDOWS-EARLY-ACCESS.md`.
