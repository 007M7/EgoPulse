# Phase 2-43: Local CD candidate verification closure

## Status

Implemented. The local CD path now verifies the exact Windows candidate it
created before reporting success.

## Decision

`cd:local` remains the release-boundary command and keeps the following order:

```text
clean worktree
    -> local CI evidence for exact HEAD
    -> optimized CLI/TUI/agentosd package
    -> candidate identity extraction
    -> archive SHA-256 + per-file SHA-256 verification
    -> binary help and TUI foundation probes
    -> daemon missing-config fail-closed probe
    -> locked production Memory Worker setup/profile probe
    -> verified unsigned early-access candidate
```

The verifier receives the candidate directory, archive path and the archive
hash emitted by the packaging process. It therefore cannot accidentally verify
an older archive left in `.artifacts/release-candidate/`.

## Why this change

Previously, `cd:local` produced a candidate but the package verifier had to be
run manually. That left the operational CD result weaker than the documented
release criteria. The new wiring makes the local delivery result atomic from an
operator's perspective: a packaging success without package-level startup and
hash evidence is no longer reported as a successful local CD.

## Cost and non-claims

The release-boundary command now spends additional time installing/checking the
packaged Memory Worker and launching the three packaged binaries. This cost is
intentional and does not enter the fast pre-push hook or ordinary local CI.
It still does not prove a configured daemon can open user stores, authenticate
Codex, provide a signed Windows binary, or admit semantic RAG/Kimi/DSH.

## Acceptance evidence

The authoritative evidence is a successful `pnpm run cd:local` (or
`pnpm run cd:local:skip-ci` with matching local CI evidence) whose output
contains:

```text
egopulse-tui_foundation_check=passed
agentosd_missing_config_fail_closed=passed
memory_worker_production_profile=passed
windows_package_verification=passed files=52
```

The first automated run completed on 2026-08-27 with
`pnpm run cd:local:skip-ci`, using the matching clean local CI evidence for
commit `d3258b320d9d6ed7682ea5a684b87c4916b69adf`. It produced and verified:

```text
archive_sha256=03af4b679270d865b940cb267ab96301f3ede80457314bded76efa9b51ebda56
egopulse-tui_foundation_check=passed
agentosd_missing_config_fail_closed=passed
memory_worker_production_profile=passed
windows_package_verification=passed files=52
```
