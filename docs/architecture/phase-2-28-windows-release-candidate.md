# Phase 2-28: Windows x64 CLI/TUI release candidate

## Status

The Windows x64 CLI/TUI release-candidate path is locally verified for
commit `b30c5aadf586c591d12d2e03e10afaf0432b43f3`. This is an unsigned early
access candidate, not a signed production release.

## Evidence

- clean local CI: all eight stages passed, including repository boundaries,
  Buf/JSON Schema/code generation, TypeScript, Tauri frontend, full Rust
  workspace and all three Python Worker projects;
- local CI evidence commit: `b30c5aadf586c591d12d2e03e10afaf0432b43f3`;
- package surfaces: `agentosd`, CLI and TUI;
- package classification: `unsigned-release-candidate`;
- package archive SHA-256:
  `ff593c00659dcdf23865b8b2c0a4aa4997006ad98f00551d5d8c02e9ba9f24ca`;
- package manifest contains 52 hashed files;
- `agentosd.exe --help`, `egopulse.exe --help` and
  `egopulse-tui.exe --help` passed from the packaged directory;
- packaged Memory Worker setup passed under CPython 3.14.4 and uv;
- the packaged production Memory Worker import path passed with no
  `fastembed` evaluation dependency present.

The local artifact was generated at:

```text
.artifacts/release-candidate/egopulse-0.1.0-b30c5aadf586-windows-x86_64-20260826T205248Z.zip
```

## Boundary

The package remains unsigned because no code-signing certificate is
available. Windows SmartScreen may display an unknown-publisher warning.
Users must verify the adjacent archive SHA-256 and the packaged `SHA256SUMS`
before extraction. This evidence does not claim SmartScreen reputation,
installer signing, Desktop/Tauri distribution, semantic/vector retrieval or a
second production Harness.

## Recovery note

The first clean-CI attempt was interrupted while pnpm was rebuilding the
workspace link layer; the failure was an environment-level `spawn EPERM`, not
a contract or source failure. The dependency tree was reconstructed from the
existing pnpm store, and the final clean-CI run completed successfully before
packaging.
