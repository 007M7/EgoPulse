# Phase 2.33 — Current Windows x64 CLI/TUI release candidate

Status: locally packaged and verified; unsigned early access

## Candidate

The candidate was built from the exact clean commit:

```text
commit: ffb699477f3aac3de8cf04778480274bdccf23e2
platform: windows-x86_64
surfaces: cli, tui
classification: unsigned-release-candidate
```

Archive:

```text
.artifacts/release-candidate/egopulse-0.1.0-ffb699477f3a-windows-x86_64-20260826T232149Z.zip
SHA-256: 6352735659755b5fdc8cc202a3fef8909fd002fe110da9bbbad6d0da9013e3d1
```

The archive contains 52 hashed files, including the `agentosd`, CLI and TUI
binaries, locked configuration/manifests, the read-only Memory Worker source,
and the contract-bindings Worker source.

## Evidence

The packaging prerequisite was a clean local CI run for the same commit:

```text
status: passed
commit: ffb699477f3aac3de8cf04778480274bdccf23e2
worktree_dirty_at_start: false
duration_ms: 50167
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
