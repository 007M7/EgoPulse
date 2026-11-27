# Restart baseline (E-001)

Recorded restart baseline for EgoPulse, taken on a clean checkout so the numbers
belong to the commit rather than to somebody's working tree.

- **Date**: 2026-11-28
- **Baseline commit**: `f5d74ed` (`main`)
- **Method**: a dedicated `git worktree` at `f5d74ed`, never the shared checkout
  that carries unrelated uncommitted work
- **Platform measured here**: Windows 11 (10.0.26200), x86_64-pc-windows-msvc
- **Result**: every gate that ran is green. The monolithic `ci:local` script did
  not complete (see §4); its gates were then run individually.

## 1. Toolchain

| Tool | Version | Note |
|---|---|---|
| Rust / Cargo | 1.98.0 | matches `rust-toolchain.toml` |
| Node.js | 24.16.0 | matches `engines.node: 24.x` |
| pnpm | 11.21.0 | matches `packageManager` and `node_modules/.modules.yaml` |
| Python | 3.13.0 | the plan asks for 3.14; every worker gate below passed on 3.13 |
| uv | 0.13.4 | |
| PowerShell | 5.1 (repo scripts) and 7.6.10 | see §5 |
| Codex CLI | **0.163.0** | pinned `0.148.0-alpha.15` in the code — see §6 |
| DSH | 0.1.5-rc.1 | recorded, nothing pins it |
| OpenCode | not installed | recorded as a baseline limitation |
| cargo-deny | 0.22.2 (E: install) | not part of `pnpm run check` |

`CARGO_TARGET_DIR` was set to `E:\dsh-targets\egopulse` so the build does not
compete with the near-full `C:` and `D:` drives.

## 2. `pnpm run check` — all eleven steps pass

Run step by step in the clean worktree, with PowerShell 5.1 for the `.ps1` steps
exactly as the npm scripts invoke them.

| Step | Exit |
|---|---|
| `check:public-boundary` | 0 |
| `check:boundaries` | 0 |
| `check:proto` | 0 |
| `check:approved-contract-change` | 0 |
| `check:contract-breaking` | 0 |
| `check:json-schema` | 0 |
| `validate-candidate` | 0 |
| `check:v01-contract-import` | 0 |
| `check:contract-codegen` | 0 |
| `check:package-integrity` | 0 |
| `check:typescript` | 0 |

Key outputs: V-01 SSOT `version=0.1.0-draft.24`, `contract_codegen=clean files=44`,
JSON Schema `schemas=15 documents=206`.

## 3. Python worker gates — all pass

| Worker | Tests |
|---|---|
| `workers/foundation-probe` | 1 passed |
| `workers/contract-bindings` | 1 passed |
| `workers/memory-rag` | 47 passed |

`uv sync --frozen` succeeded for all three, so the frozen lockfiles are consistent
with the environment. Python 3.13 did **not** block any worker gate, which answers
the open question about the 3.14 requirement: nothing here requires 3.14.

## 4. `ci:local` did not complete — and that is a finding, not a flake

The monolithic `scripts/local-ci.ps1` was started twice. Both runs sat for over 25
minutes having consumed only ~77 seconds of CPU, with no `.local-ci/evidence`
directory produced (the script writes its evidence at the end), no `cargo` or
`uv` process alive, and a 288 MB target directory. It was stopped rather than left
running indefinitely.

Its gates were then run individually, which is where the numbers in §2 and §3 come
from. At the time of writing, `scripts/check-rust.ps1` (the heaviest remaining
gate) had not finished, so this document does **not** claim it passed.

Treat this as an unresolved observation: the script appears to block somewhere
between the TypeScript gate and the Rust gate. It is recorded rather than repaired
because repairing it is not part of a baseline PR, and because a gate that hangs
silently is worse than one that fails.

## 5. Environment traps worth recording

- **`cargo` must be on `PATH`.** `scripts/contract-codegen.ps1` falls back to
  `%USERPROFILE%\.cargo\bin\cargo.exe` when `Get-Command cargo` fails, and this
  machine installs the toolchain under a non-default prefix. The resulting
  `Cargo is missing: ...` message reads like a repository defect and is not one.
- **PowerShell 5.1 and 7.6 disagree about deleting an environment variable.**
  After `[Environment]::SetEnvironmentVariable(name, $null, 'Process')`:

  | Host | `Test-Path Env:<name>` |
  |---|---|
  | Windows PowerShell 5.1 | `False` (deleted) |
  | PowerShell 7.6.10 | `True` (present, empty) |

  `scripts/test-windows-package-integrity.ps1` asserts the variable was restored to
  *absent*, so it passes under 5.1 and fails under 7.6. The npm scripts use 5.1
  today. Any move to PowerShell 7 — including the planned `xtask` migration —
  has to fix the restore semantics first, otherwise the gate turns red for a
  reason unrelated to the change being made.

## 6. Codex CLI drifted from the pinned protocol version

The code and the contract fixtures pin `codex-app-server-v2-0.148.0-alpha.15`
(`CODEX_CAPABILITY_PROFILE_ID`, `contracts/fixtures/harness/v1/*.json`,
`config/agentos-config.example.json`). The installed CLI is **0.163.0**.

A read-only probe of the installed binary (`codex --version`, `codex --help`,
`codex app-server --help`) shows the surface EgoPulse binds to has changed:

- `app-server` gained a transport option: `--listen stdio:// | unix://PATH | ws://IP:PORT | off`
  (default `stdio://`). A WebSocket transport did not exist as a first-class
  option in the pinned version.
- That transport brings its own authentication surface: `--ws-auth`
  (`capability-token`, `signed-bearer-token`), `--ws-token-file`,
  `--ws-token-sha256`, `--ws-shared-secret-file`, `--ws-issuer`, `--ws-audience`,
  `--ws-max-clock-skew-seconds`.
- `app-server` exposes `generate-json-schema` and `generate-ts`, which is the
  mechanism for producing the protocol digest a capability profile needs — the
  digest pinned today cannot be reproduced from the installed binary.
- New subcommands `agents`, `plugin`, `remote-control`, `doctor`, `sandbox`,
  `debug`, `apply`; and `--code-mode-host`, `--strict-config` flags.

Nothing was executed against a model and no contract file was touched. This is
input for `E-002`, which must re-derive the profile digest under a
`[合约]` change rather than assume the old digest still describes the surface.

## 7. What is not covered

- Linux and macOS: CI only (`E-504` / `E-505`). The only reachable Linux host has
  no Rust toolchain, 2 GB RAM and ~7 GB free disk, and is shared with unrelated
  active projects; building there would put another project's data at risk.
- `desktop-frontend` (`pnpm --filter @egopulse/desktop run build`) was not run to
  completion as part of these gates.
- `ci:local` as a single command, per §4.
- OpenCode adapter behaviour — the binary is not installed.
