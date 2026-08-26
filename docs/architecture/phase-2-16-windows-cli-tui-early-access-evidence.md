# Phase 2-16 Windows CLI/TUI early-access evidence

- Status: `candidate_built_and_smoke_verified`
- Date: 2026-08-26
- Scope: Windows x64, CLI + TUI first release surface
- Desktop/Tauri: not included in this phase
- Signing: unsigned; SmartScreen unknown-publisher risk remains accepted for
  early access only

## Build evidence

The candidate was built from clean commit `b489cf7a29cb67f929f6a11e883b5c6a08b36494`,
which is pushed to the EgoPulse remote branch. The authoritative local CI
completed all eight steps with `status=passed` and
`worktree_dirty_at_start=false`:

1. Git diff integrity
2. Locked Node manifest
3. Contract, repository-boundary and TypeScript checks
4. Desktop frontend build (verification only; Desktop is not packaged)
5. Rust workspace tests and release prerequisites
6. Python foundation probe
7. Python contract bindings
8. Memory/RAG Worker tests

The package command reused the clean local-CI evidence and produced:

```text
classification=unsigned-release-candidate
platform=windows-x86_64
archive=egopulse-0.1.0-b489cf7a29cb-windows-x86_64-20260826T100139Z.zip
archive_sha256=e8d1286356d982e54b35248311f87b95dcfbd851671068559efbd0b386c4163f
```

The local candidate directory is under `.artifacts/release-candidate/` and is
ignored by Git. `BUILD-METADATA.json` and `SHA256SUMS` inside the candidate are
the per-build source of truth; this document records the handoff evidence, not
an uploaded public release asset.

## Package and installation checks

- `BUILD-METADATA.json` records `surfaces=[cli,tui]`, local CI provenance and
  `packaged-source-locked-python` for the Memory Worker.
- `SHA256SUMS` contains hashes for all executables, configs, locks, generated
  bindings and Worker sources.
- `setup-memory-worker.ps1` created the package-local Python 3.14 environment
  with the frozen production dependency set.
- The packaged retrieval module imported successfully.
- `fastembed` was absent from the package-local production environment. The
  FastEmbed model experiments therefore remain evaluation-only and do not
  silently increase the first-release install size or memory footprint.
- `egopulse.exe --help`, `egopulse-tui.exe --help` and `agentosd.exe --help`
  all exited successfully.
- The archive SHA-256 matched the build output exactly.

The checks are now repeatable with the repository verifier (the previous run
was performed against the candidate directory above):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/verify-windows-package.ps1 `
  -PackageRoot .artifacts/release-candidate/<candidate> `
  -ArchivePath .artifacts/release-candidate/<candidate>.zip `
  -ExpectedArchiveSha256 <sha256> `
  -VerifyMemoryWorker
```

## Release boundary

This evidence closes the local Windows CLI/TUI candidate build loop. It does
not close any of the following:

- code signing and SmartScreen reputation;
- authenticated Kimi lifecycle or second-Harness admission;
- multi-model production scheduling;
- production semantic/vector retrieval or reranking;
- Desktop/Tauri packaging;
- a public GitHub Release upload.

Those remain explicit follow-up gates. In particular, the E5-small comparison
is still a Founder packaging decision, not a production dependency decision.
