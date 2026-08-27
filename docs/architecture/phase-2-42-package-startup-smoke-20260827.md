# Phase 2-42: Windows package startup smoke gate

## Status

Implemented in the local release verifier. This is a package-integrity and
fail-closed startup check; it does not change the frozen architecture or admit
Desktop, semantic RAG, Kimi or DSH.

## Finding

The package verifier already checked file hashes and `--help` for `agentosd`,
CLI and TUI. That was necessary but insufficient: a malformed or incorrectly
linked package could still pass help while failing on a safe first-run path.

## Decision

The Windows package verifier now exercises two bounded probes:

1. `egopulse-tui.exe --foundation-check` must exit successfully without a
   daemon or raw terminal mode.
2. `agentosd.exe --check-config` must return exit code `78` when pointed at an
   intentionally missing user configuration.

The second probe temporarily overrides `EGOPULSE_USER_CONFIG` and restores the
caller's original environment value. It therefore proves the packaged daemon's
fail-closed behavior without depending on, or mutating, a developer's ambient
configuration.

## Why this change

It tests the first-run boundary that a Windows user can reach immediately and
turns a safety invariant into package evidence. It is cheaper and more
deterministic than starting a fully configured daemon, opening SQLCipher
stores, or exercising a real Harness during every package verification.

## Cost and non-claims

The verifier now depends on the documented exit-code contract for
`agentosd --check-config`; changing that contract requires updating the package
gate and evidence. The probes still do not prove a configured daemon can open
all stores, that the external Codex executable is installed, or that the
unsigned archive will avoid SmartScreen warnings.

## Acceptance evidence

The authoritative evidence is a local `scripts/verify-windows-package.ps1`
run against a clean, commit-bound candidate. Expected additional lines are:

```text
egopulse-tui_foundation_check=passed
agentosd_missing_config_fail_closed=passed
windows_package_verification=passed
```

The current Windows x64 candidate was executed on 2026-08-27 through the
automated local CD path, with the following observed result:

```text
egopulse.exe_help=passed
egopulse-tui.exe_help=passed
agentosd.exe_help=passed
egopulse-tui_foundation_check=passed
agentosd_missing_config_fail_closed=passed
memory_worker_setup=passed
memory_worker_production_profile=passed
windows_package_verification=passed files=52
```

The candidate is bound to code commit
`d3258b320d9d6ed7682ea5a684b87c4916b69adf` and archive SHA-256
`03af4b679270d865b940cb267ab96301f3ede80457314bded76efa9b51ebda56`.
