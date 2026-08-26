# Phase 2-16 Windows CLI/TUI early-access evidence

- Status: `candidate_built_and_package_verified`
- Date: 2026-08-27
- Scope: Windows x64, CLI + TUI first release surface
- Desktop/Tauri: not included in this phase
- Signing: unsigned; SmartScreen unknown-publisher risk remains accepted for
  early access only

## Build evidence

The candidate was built from clean commit `6a6e764d9faa8bb09cfcd6d9e3445c370781dfdf`,
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
archive=egopulse-0.1.0-6a6e764d9faa-windows-x86_64-20260826T175654Z.zip
archive_sha256=df6856594ea97b99158bfb632813f489ad5614b0330649b7d219204ae3f21b08
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
  with the frozen production dependency set; the package-local executable was
  verified at `workers/memory-rag/.venv/Scripts/python.exe`.
- The packaged retrieval module imported successfully.
- `fastembed` was absent from the package-local production environment. The
  FastEmbed model experiments therefore remain evaluation-only and do not
  silently increase the first-release install size or memory footprint.
- `egopulse.exe --help`, `egopulse-tui.exe --help` and `agentosd.exe --help`
  all exited successfully.
- The verifier checked all 52 entries in `SHA256SUMS`, including the packaged
  binaries, configuration, locks, generated bindings and Worker sources.
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
