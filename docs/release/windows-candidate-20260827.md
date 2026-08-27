# Windows x64 early-access candidate evidence

- Date: 2026-08-27
- Repository: `007M7/EgoPulse`
- Commit: `aa0bf0b33244947e97c43ee96bb241a022c1affd`
- Classification: `unsigned-release-candidate`
- Included surfaces: CLI and TUI over the shared Rust client kernel
- Desktop: intentionally excluded from this first candidate

## Local CI evidence

The full local CI gate passed from a clean worktree at the exact candidate
commit. All eight stages passed in `52,084 ms`:

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

- Archive: `egopulse-0.1.0-aa0bf0b33244-windows-x86_64-20260827T104825Z.zip`
- Archive SHA-256:
  `031c2c3730dfe88a690909bee63547987fe1a9a67cb0654c007feb9c3669c419`
- Package verification: passed, `files=55`
- `egopulse.exe --help`: passed
- `egopulse-tui.exe --help`: passed
- `agentosd.exe --help`: passed
- TUI non-interactive foundation probe: passed
- daemon missing-configuration fail-closed probe: passed
- isolated Memory Worker setup: passed
- locked production Memory Worker profile: passed

## Isolated installation smoke

The packaged `install-egopulse.ps1` was run with an isolated data directory,
`-NoPersistEnvironment`, and without launching the daemon. It completed
successfully and printed these redacted Provider facts:

```text
gpt-codex-default      executable_available=True  credential_status=harness_account_delegated admission=production
deepseek-dsh-candidate  executable_available=True  credential_status=missing                 admission=held
kimi-cli-candidate      executable_available=True  credential_status=missing                 admission=held
glm-opencode-candidate  executable_available=False credential_status=harness_account_delegated admission=held
```

No user environment variable was persisted, no API-key value was read into
the report, and no Provider inference request was sent.

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
