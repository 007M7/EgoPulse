# Phase 2.33 — Current Windows x64 CLI/TUI release candidate

Status: locally packaged and verified; unsigned early access

## Candidate

The candidate was built from the exact clean commit:

```text
commit: abcbc9c99dee97907d5279cf4743da2c7d01a4fe
platform: windows-x86_64
surfaces: cli, tui
classification: unsigned-release-candidate
```

Archive:

```text
.artifacts/release-candidate/egopulse-0.1.0-abcbc9c99dee-windows-x86_64-20260826T222815Z.zip
SHA-256: bdf72ea5183b429ac93554ceef4af66eff68ad96cb2874c477f06706c5e52a20
```

The archive contains 52 hashed files, including the `agentosd`, CLI and TUI
binaries, locked configuration/manifests, the read-only Memory Worker source,
and the contract-bindings Worker source.

## Evidence

The packaging prerequisite was a clean local CI run for the same commit:

```text
status: passed
commit: abcbc9c99dee97907d5279cf4743da2c7d01a4fe
worktree_dirty_at_start: false
duration_ms: 45622
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
