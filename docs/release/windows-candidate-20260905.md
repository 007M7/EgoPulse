# Windows x64 CLI/TUI early-access candidate evidence

- Date: 2026-09-05
- Repository: `007M7/EgoPulse`
- Commit: `5c8a1e871a59b38f9aa82036eceaf58ddda87882`
- Classification: `unsigned-release-candidate`
- Included surfaces: CLI and TUI, backed by `agentosd` and the shared Rust
  Client Kernel

## Local CI evidence

The canonical local CI gate passed from a clean worktree at the exact candidate
commit in `91,950 ms`. Contract, boundary and TypeScript checks; the complete
Rust workspace; the hermetic installer check; and all three Python Worker gates
passed. The real-process daemon fixture passed all `38` tests serially, and the
daemon library passed all `133` tests serially.

The machine-readable source is `.local-ci/evidence/latest.json`. That local path
is ignored by Git, and the exact evidence used for packaging is retained inside
the archive at `manifests/local-ci-evidence.json`.

## Governed Provider and Harness boundary

The candidate proves that one exact synthetic GPT model can be composed through
both the Codex app-server driver and the DSH ACP driver while retaining isolated
stores and the same governed model identity. This is a driver-composition proof;
it does not invoke a remote model or claim authentication for either route.

The only production-admitted route remains GPT through the Codex app-server
Harness. DeepSeek, Kimi and GLM/OpenCode profiles may be represented as held
candidates, but they remain non-selectable until their own authentication,
capability and acceptance evidence is approved. Their real authentication is
therefore not a phase-one release blocker and has not been misreported as
complete.

## Memory/RAG boundary

The packaged Memory Worker uses the locked production profile and read-only
accepted snapshots. Lexical retrieval is the admitted phase-one path.
Semantic/vector retrieval and model-backed evaluation remain reversible
evaluation candidates; they cannot mutate accepted Memory facts or activate
themselves.

## Package evidence

- Archive:
  `egopulse-0.1.0-5c8a1e871a59-windows-x86_64-20260905T065917Z.zip`
- Archive SHA-256:
  `cf85884e0572a30e5e350c17ec09941f844dba78209e42f0f05bb8dac9bbb5c3`
- Package verification: passed, `files=55`
- CLI, TUI and daemon `--help`: passed
- TUI non-interactive foundation check: passed
- daemon missing-configuration fail-closed check: passed
- isolated Memory Worker setup: passed
- locked production Memory Worker profile: passed

The package is usable for local CLI/TUI testing after the user supplies the
required local configuration and Provider credentials. It is unsigned, so
Windows SmartScreen may show an unknown-publisher warning.

## Distribution boundary

This evidence authorizes local/manual early-access testing of the Windows x64
CLI/TUI slice. It does not claim:

- a signed binary or SmartScreen reputation;
- authenticated production admission for DeepSeek, Kimi or GLM/OpenCode;
- semantic/vector RAG production admission;
- native Desktop GUI acceptance or Desktop distribution;
- final public GitHub Release approval or automatic model substitution.

Users must verify the ZIP hash and read `WINDOWS-EARLY-ACCESS.md` before
installation.
