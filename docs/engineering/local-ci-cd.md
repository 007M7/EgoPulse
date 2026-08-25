# Local CI/CD and repository classification

## Decision

The authoritative engineering gate runs in GitHub Actions for pull requests, `main` pushes and release tags. The workflow owns the reproducible Windows runner, exact-SHA CI evidence and the release dependency chain. Local checks remain useful for fast feedback and offline reproduction, but are not repeated as a mandatory full Rust gate before every push. Release operations produce an unsigned, commit-bound Windows early-access candidate; they do not imply code signing or a production release.

The two repositories have different classifications:

| Repository | Classification | Permitted content |
| --- | --- | --- |
| `EgoPulse` | Product implementation | Source, contracts, generated bindings, tests, public implementation ADRs and operator documentation required to build or maintain the product |
| `founder-agent-os` | Private governance | Founder decisions, Gate records, review evidence, methodology, research synthesis, planning and governance automation |

Private governance material must not be copied into `EgoPulse`. `pnpm run check:public-boundary` fails when tracked files appear under a reserved private-governance root or use a credential-bearing file type. This keeps the implementation repository suitable for later publication without relying on deleting reachable Git history.

## Local fast pre-push check

Install the repository hook once per clone or worktree:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install-git-hooks.ps1
```

The tracked hook runs the fast, non-release check:

- `git diff --check`;
- repository boundaries, contracts, generated bindings and TypeScript checks.

This deliberately does not compile and test the complete Rust workspace on every push; that expensive authoritative gate runs once in GitHub Actions.

Run the fast check directly with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/pre-push-check.ps1
```

## Local full CI

Run the complete local reproduction gate only when working offline, diagnosing a failure, or validating a risky Rust change:

```powershell
pnpm run ci:local
```

Bootstrap a new checkout once with `pnpm install --frozen-lockfile`. The recurring gate verifies Git diff integrity, Node manifest/lock consistency without reinstalling an already materialized dependency tree, repository boundaries, contracts, generated code, TypeScript, the Desktop frontend, the complete Rust workspace, and all three Python projects, including the Memory/RAG Worker. Missing or stale installed packages fail closed in the TypeScript or Desktop steps. Machine-readable evidence is written beneath `.local-ci/evidence/` and is intentionally ignored by Git.

Why keep a tracked fast hook: it catches contract and boundary failures before a push without duplicating the long remote Rust job. Git hooks can still be bypassed with `--no-verify`; GitHub required checks remain the authoritative control.

## Local CD

Create a release candidate with:

```powershell
pnpm run cd:local
```

`pnpm run cd:local` is an offline reproduction command. It runs local CI once, then calls the shared Windows packaging script. If local CI has already passed for the same clean `HEAD`, use `pnpm run cd:local -- -SkipCi` to avoid rerunning it. The first candidate packages the shared kernel as three Windows x64 binaries: `agentosd.exe`, `egopulse.exe` and `egopulse-tui.exe`, plus the public configuration templates required for first-run setup. Desktop packaging is an explicit later-phase opt-in via `scripts/package-windows.ps1 -IncludeDesktop`. The packaging script requires a clean worktree, includes dependency locks and available CI evidence, generates per-file SHA-256 hashes, and creates a ZIP plus an archive hash beneath `.artifacts/release-candidate/`. The packaging-only command is `pnpm run package:windows`.

The candidate is explicitly classified as `unsigned-release-candidate`. It must not be represented as a production release. Code signing, SBOM generation, protected release approval and remote provenance attestation remain release-Gate requirements.

## GitHub CI/CD

`.github/workflows/ci.yml` runs three parallel CI jobs—Rust, TypeScript/contracts and Python—on pull requests, `main` pushes and `v*` tags. The `windows-cd` job is conditional: it requires those same three jobs from the current workflow run, then runs only the optimized Windows release build and packaging step. It does not rerun `local-ci.ps1` or the full test suite.

For a candidate without creating a release tag, use the workflow-dispatch input `publish_candidate=true`; the package is uploaded as a workflow artifact. Pushing a `v*` tag additionally creates a GitHub prerelease with the ZIP and `.sha256` file. Until a code-signing certificate exists, the release remains explicitly unsigned and must document SmartScreen risk.

This gives the normal path:

```text
local fast check -> one remote CI run -> dependent remote Windows CD
```

The release build is not a duplicate test gate: it produces optimized binaries that the debug/test CI job does not produce. Within the first CD path, only the three CLI/TUI/kernel binaries are compiled; the Tauri CLI installer path and desktop frontend are intentionally not invoked until the desktop vertical is ready. Local full CI/CD remains an opt-in diagnostic and offline path.
