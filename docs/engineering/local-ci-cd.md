# Local CI/CD and repository classification

## Decision

Until the private GitHub repository can enforce protected branches and protected release environments, the authoritative engineering gate runs locally. Every code push must pass the tracked pre-push hook. Release operations produce an unsigned, commit-bound Windows candidate; they do not publish a production release.

The two repositories have different classifications:

| Repository | Classification | Permitted content |
| --- | --- | --- |
| `EgoPulse` | Product implementation | Source, contracts, generated bindings, tests, public implementation ADRs and operator documentation required to build or maintain the product |
| `founder-agent-os` | Private governance | Founder decisions, Gate records, review evidence, methodology, research synthesis, planning and governance automation |

Private governance material must not be copied into `EgoPulse`. `pnpm run check:public-boundary` fails when tracked files appear under a reserved private-governance root or use a credential-bearing file type. This keeps the implementation repository suitable for later publication without relying on deleting reachable Git history.

## Local CI

Install the repository hook once per clone or worktree:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install-git-hooks.ps1
```

Run the same gate directly with:

```powershell
pnpm run ci:local
```

Bootstrap a new checkout once with `pnpm install --frozen-lockfile`. The recurring gate verifies Git diff integrity, Node manifest/lock consistency without reinstalling an already materialized dependency tree, repository boundaries, contracts, generated code, TypeScript, the Desktop frontend, the complete Rust workspace, and both Python projects. Missing or stale installed packages fail closed in the TypeScript or Desktop steps. Machine-readable evidence is written beneath `.local-ci/evidence/` and is intentionally ignored by Git.

Why a tracked hook instead of relying on developer memory: it makes the gate the default for every push and keeps the command reviewable with the source. The cost is slower pushes and local machine prerequisites. Git hooks can still be bypassed with `--no-verify`, so this is an interim control rather than a substitute for remote required checks.

## Local CD

Create a release candidate with:

```powershell
pnpm run cd:local
```

CD reruns local CI, requires a clean worktree and evidence matching the exact `HEAD`, builds all four Windows binaries, includes dependency locks and CI evidence, generates per-file SHA-256 hashes, and creates a ZIP plus an archive hash beneath `.artifacts/release-candidate/`.

The candidate is explicitly classified as `unsigned-release-candidate`. It must not be represented as a production release. Code signing, SBOM generation, protected release approval and remote provenance attestation remain release-Gate requirements.

Why a candidate pipeline now: packaging layout and commit traceability are expensive to change late and affect every delivery surface. Why not automatic production publishing: the product is still in Gate 4 and no trusted Windows signing identity or protected remote release environment has been bound. The cost is a manual promotion step and duplicated local/remote verification when remote enforcement becomes available.
