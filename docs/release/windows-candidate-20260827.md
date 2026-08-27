# Windows x64 early-access candidate evidence

- Date: 2026-08-27
- Repository: `007M7/EgoPulse`
- Commit: `3d9c42c24de4ab4d1e72053de0fbc0e8c2c6c5ca`
- Classification: `unsigned-release-candidate`
- Included surfaces: CLI and TUI over the shared Rust client kernel
- Desktop: intentionally excluded from this first candidate

## Local CI evidence

The full local CI gate passed from a clean worktree at the exact candidate
commit. All eight stages passed in `52,442 ms`:

1. Git diff integrity
2. Locked Node manifest
3. Contracts, repository boundaries and TypeScript
4. Desktop frontend build
5. Rust workspace
6. Python foundation probe
7. Python contract bindings
8. Python Memory/RAG Worker

The machine-readable source is `.local-ci/evidence/latest.json`. That path is
ignored by Git; the candidate package contains a copy at
`manifests/local-ci-evidence.json`.

## Package evidence

- Archive: `egopulse-0.1.0-3d9c42c24de4-windows-x86_64-20260827T095649Z.zip`
- Archive SHA-256:
  `86aa3185a0076b0375c894fb41e5d05c0aad240ea4c2b8a2454bbee5626b4ca2`
- Package verification: passed, `files=55`
- `egopulse.exe --help`: passed
- `egopulse-tui.exe --help`: passed
- `agentosd.exe --help`: passed
- TUI non-interactive foundation probe: passed
- daemon missing-configuration fail-closed probe: passed
- isolated Memory Worker setup: passed
- locked production Memory Worker profile: passed

The package verifier created the Worker environment inside the candidate
directory and validated that retrieval remains a read-only, lexical baseline.
It did not promote semantic/vector retrieval or any Provider admission.

## Distribution boundary

This evidence authorizes a local/manual early-access test of the CLI/TUI
candidate. It does not claim:

- a signed binary or SmartScreen reputation;
- Desktop product completeness;
- authenticated production admission for DeepSeek, Kimi or GLM;
- semantic/vector RAG production admission;
- final release approval or automatic model substitution.

Users must verify the published ZIP hash and read `WINDOWS-EARLY-ACCESS.md`.
