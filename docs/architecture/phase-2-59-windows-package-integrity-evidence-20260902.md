# Phase 2-59 — Windows package integrity evidence

- Date: 2026-09-02
- Scope: repository Windows package construction and verification scripts
- Status: synthetic gate implemented; real local-CD remains pending

## Evidence boundary

This slice adds a shared Windows package-integrity implementation and a fast,
purely synthetic test. The test creates temporary package trees and ZIP files;
it does not build release binaries, download `uv`, construct a release
candidate, or execute packaged applications.

Accordingly, this evidence does not prove:

- that a real local-CD candidate has been built and verified;
- that release executables run after extraction;
- Memory Worker setup from a release package;
- archive provenance, Authenticode, or release signing.

## Proven synthetic checks

The shared gate verifies that:

- package and ZIP paths are safe relative paths, unique both ordinally and
  under `OrdinalIgnoreCase`, and do not use Windows device names, ADS, absolute
  paths, empty segments, or traversal segments; normalized paths are bounded
  to 1,024 UTF-8 bytes, 64 segments, and 255 UTF-8 bytes per segment;
- package files are ordinary files; reparse points are rejected and a Windows
  metadata handle must prove `NumberOfLinks == 1`, with unreadable link counts
  failing closed;
- `SHA256SUMS` is strictly parsed, cannot list itself, exactly closes over the
  package file set, includes `config/agentos-config.example.json`, and matches
  every file digest;
- archive path and expected SHA-256 are paired, the expected digest is strict,
  and the archive digest is checked before ZIP parsing;
- one read-only shared file handle binds hashing, complete ZIP preflight, and
  extraction, eliminating a path reopen between those phases;
- ZIP entry kind, path set, unique top-level directory, expanded sizes, entry
  count, and compression ratio are bounded before any extraction;
- the ZIP path tree models implicit and explicit directories, so file/child
  conflicts in either entry order and ancestor case drift fail before a
  temporary extraction directory is created;
- extraction uses a unique empty GUID root, validates containment, and never
  overwrites an existing destination;
- source and extracted trees each have a closed manifest and then compare by
  exact complete file set and per-file SHA-256, including `SHA256SUMS`;
- `PYTHONPATH` and `EGOPULSE_USER_CONFIG` are restored after success and
  failure, including when they were initially absent;
- package construction creates the candidate root and every descendant target
  directory with atomic `CreateDirectoryW` calls, copies and writes every
  candidate file with `FileMode.CreateNew`, and refuses pre-existing or racing
  targets; local-CD accepts exactly one complete candidate identity tuple.

The synthetic matrix covers the happy path plus manifest and ZIP extra,
missing, duplicate, case-collision, unsafe-path, link, hash-mismatch,
implicit/explicit path-tree conflict, top-level, expected-digest, entry-count,
expanded-size, compression-ratio, link-count read failure, and exclusive
creation failures. A synchronized two-writer test invokes the same public-tree
copy seam used by the packager and proves exactly one winner and one atomic
directory-creation failure.

## Verification

The focused gate is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-windows-package-integrity.ps1
```

It is registered as `pnpm run check:package-integrity` and is part of
`pnpm run check`. Both the focused command and the complete repository check
passed locally on 2026-09-02, with the focused command reporting
`windows_package_integrity_test=passed`. This phase records only the synthetic
result; a real `scripts/local-cd.ps1` run remains an explicit later release
operation.
