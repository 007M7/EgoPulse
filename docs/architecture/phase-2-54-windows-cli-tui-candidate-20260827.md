# Phase 2-54 — Current Windows x64 CLI/TUI early-access candidate

- Date: 2026-08-27
- Scope: `agentosd`, CLI, TUI and packaged read-only Memory/RAG Worker
- Status: locally packaged and verified; unsigned early-access candidate
- Commit: `38d665b68a35d8d736e70beb20495c78bd7d1b3c`

## Candidate identity

```text
platform: windows-x86_64
surfaces: cli, tui
archive: .artifacts/release-candidate/egopulse-0.1.0-38d665b68a35-windows-x86_64-20260827T142127Z.zip
archive SHA-256: 0733c03a3613893af24faa12bc78b158a66eb57d76fc8d88913e7c108fa0d936
classification: unsigned-release-candidate
```

The package contains 55 hashed files, `agentosd.exe`, `egopulse.exe`,
`egopulse-tui.exe`, the locked Python Worker sources and the one-click setup
scripts. It deliberately does not include the Desktop executable; Desktop
distribution remains a separate Stage 5 acceptance item.

## Evidence

The exact clean commit had already passed local CI with all eight steps. The
release build then produced the three declared binaries, and package creation
completed with `ci_provider=local`. The package verifier passed:

```text
archive_sha256=0733c03a3613893af24faa12bc78b158a66eb57d76fc8d88913e7c108fa0d936
egopulse.exe_help=passed
egopulse-tui.exe_help=passed
agentosd.exe_help=passed
egopulse-tui_foundation_check=passed
agentosd_missing_config_fail_closed=passed
memory_worker_setup=passed
memory_worker_production_profile=passed
windows_package_verification=passed files=55
```

Memory Worker setup used CPython 3.14.4 and a package-local `uv` cache. The
package does not contain or resolve any Provider secret.

## Release interpretation

This is usable for local CLI/TUI testing after the user supplies the required
configuration and API credentials. It is not a signed production release:
Windows SmartScreen may show an unknown-publisher warning. Semantic/vector
retrieval remains non-default, and DeepSeek, Kimi and GLM/OpenCode remain
candidate/held Provider routes until their independent authenticated lifecycle
and recovery evidence is accepted.

The candidate was created with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/package-windows.ps1 \
  -ArtifactRoot .artifacts/release-candidate \
  -CiEvidencePath .local-ci/evidence/latest.json \
  -CiProvider local
```

It was verified with `scripts/verify-windows-package.ps1` using the archive
hash above and `-VerifyMemoryWorker`.

The current candidate was produced from a clean worktree after the Windows
GitHub transport hardening change. Local CI evidence for the exact commit is
`.local-ci/evidence/latest.json`, with all eight steps passed in 67,671 ms.

## Separate Desktop-inclusive candidate

The same local CI evidence was also used to build a separate Desktop-inclusive
candidate from documentation commit `03358f8e73136d607e85cb13266a9876184c0f10`:

```text
archive: .artifacts/release-candidate/egopulse-0.1.0-03358f8e7313-windows-x86_64-20260827T130801Z.zip
archive SHA-256: 74b19ea55e2dac818bb3ae27f68a2e40a4b8cad7fa577b48b220db90e1defb8d
surfaces: cli, tui, desktop
files: 56
```

The verifier reported `egopulse-desktop.exe_present=passed` and
`windows_package_verification=passed files=56`, alongside the same CLI/TUI,
daemon and Memory Worker probes. This candidate proves packaging and binary
presence only. Native Tauri GUI automation, remaining Desktop workflows and
first-run GUI acceptance remain open Stage 5 items.
