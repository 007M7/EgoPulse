# Phase 2.33 — Current Windows x64 CLI/TUI release candidate

Status: locally packaged and verified; unsigned early access

## Candidate

The candidate was built from the exact clean commit:

```text
commit: 34a3fc79d45eea2e281190d795ed7666ae8715c8
platform: windows-x86_64
surfaces: cli, tui
classification: unsigned-release-candidate
```

Archive:

```text
.artifacts/release-candidate/egopulse-0.1.0-34a3fc79d45e-windows-x86_64-20260826T223958Z.zip
SHA-256: 88afb148548cd0f747339fca29a6b4461c5fd5019415ccd8287dc96982878b12
```

The archive contains 52 hashed files, including the `agentosd`, CLI and TUI
binaries, locked configuration/manifests, the read-only Memory Worker source,
and the contract-bindings Worker source.

## Evidence

The packaging prerequisite was a clean local CI run for the same commit:

```text
status: passed
commit: 34a3fc79d45eea2e281190d795ed7666ae8715c8
worktree_dirty_at_start: false
duration_ms: 52463
all 8 local CI stages: passed
```

The package verifier passed:

- archive SHA-256 matched the recorded digest;
- `egopulse.exe --help` passed;
- `egopulse-tui.exe --help` passed;
- `agentosd.exe --help` passed;
- all 52 package file hashes matched `SHA256SUMS`;
- Memory Worker setup passed under CPython 3.14.4 and uv;
- production Worker import passed with no `fastembed` evaluation dependency.

## Release boundary

This is the current CLI/TUI early-access candidate, not a signed production
release. No code-signing certificate is available, so Windows SmartScreen may
show an unknown-publisher warning. Users must verify the adjacent archive
`.sha256` file before extraction.

The package does not claim Desktop distribution, semantic/vector retrieval,
remote telemetry, enterprise identity or a second production Harness. The
Memory Worker is packaged as a locked, supervised, read-only process over
accepted snapshots; candidate mutation remains governed by the Rust Memory
Authority described in Phase 2.32.
