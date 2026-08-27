# Windows x64 early-access candidate evidence

- Date: 2026-08-27
- Repository: `007M7/EgoPulse`
- Commit: `5eb7b327ebf0ec26a418356fee26810b37c9c853`
- Classification: `unsigned-release-candidate`
- Included surfaces: CLI, TUI and Desktop over the shared Rust client kernel

## Local CI evidence

The full local CI gate passed from a clean worktree at the exact candidate
commit. All eight stages passed in `66,309 ms`:

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

- Archive: `egopulse-0.1.0-5eb7b327ebf0-windows-x86_64-20260827T112524Z.zip`
- Archive SHA-256:
  `b9e7a88fc35959a00eb7f1c80edb21e3d5191f1ed9a5f13ba2a7bee5366fb5f7`
- Package verification: passed, `files=56`
- `egopulse.exe --help`: passed
- `egopulse-tui.exe --help`: passed
- `agentosd.exe --help`: passed
- `egopulse-desktop.exe` present and non-empty: passed
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

This evidence authorizes a local/manual early-access test of the CLI/TUI and
Desktop candidate. It does not claim:

- a signed binary or SmartScreen reputation;
- authenticated production admission for DeepSeek, Kimi or GLM;
- semantic/vector RAG production admission;
- final release approval or automatic model substitution.

Users must verify the published ZIP hash and read `WINDOWS-EARLY-ACCESS.md`.
