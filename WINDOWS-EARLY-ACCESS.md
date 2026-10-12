# Windows x64 early access

This package is the Windows x64 CLI/TUI early-access candidate of EgoPulse.
These instructions apply to the matching phase-one repair candidate. Check
`BUILD-METADATA.json` for its commit; the previous published
`v0.1.0-early-access.1` archive predates this repository work-loop repair.
CLI, TUI and `agentosd.exe` use the same Rust Client Kernel and local IPC
transport. Desktop is implemented as a separate shared-kernel candidate, but
is intentionally excluded from this first CLI/TUI package until native GUI
automation and the remaining Desktop workflows are accepted.

The package is intentionally **unsigned**. Windows SmartScreen may show an
unknown-publisher warning. Verify the downloaded archive with the adjacent
`.sha256` file before extracting it; the package also contains `SHA256SUMS`
for per-file verification. Do not treat an unsigned candidate as a production
release.

## Install for repository work

After extracting the archive to a short path such as `C:\EgoPulse`, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-egopulse.ps1 `
  -RepositoryRoot 'D:\work\project' `
  -AcceptanceContractPath 'D:\work\project-acceptance.json' -Launch
```

The installer creates a user-owned configuration under
`%LOCALAPPDATA%\EgoPulse`, generates the ten local Authority/read-model
encryption and session keys as user environment variables, installs the locked Memory Worker,
performs `agentosd --check-config`, and launches the daemon. It never writes
Provider API keys to the package or configuration. A pre-existing
configuration is preserved unless `-Force` is explicitly supplied; forced
replacement creates a timestamped backup.

Keep the reviewed acceptance contract outside the execution checkout and
follow [repository setup](config/README.md#governed-repository-setup).
Require `verification_preflight=repository_configured` before starting work.
Without the repository parameters, installation sets up only the base product;
`verification_preflight=not_configured` means the real repository checker
path still needs configuration.

After configuration validation, the installer prints one redacted preflight
line per configured Provider. `executable_available` checks only the configured
path/PATH entry, while `credential_status` reports API-key environment presence
or Harness-owned delegated login. These are local readiness hints, not
authenticated lifecycle or production-admission evidence.

The installer requires Windows x64, CPython 3.14.x, an installed `uv` command,
and the executable of the configured production Harness with an authenticated
account for the exact selected model. A GPT/Codex profile needs Codex
0.148.0-alpha.15 to resolve to a local application; a DeepSeek profile needs
the executable of its own Harness instead, so installation can complete. If `uv` is absent, install it
from `https://docs.astral.sh/uv/` first. A configured command is resolved to an
absolute executable before daemon process supervision; an unavailable
production Harness fails installation instead of surfacing on the first Task.
EgoPulse repeats executable-file validation immediately before every child
process spawn and assigns the process tree to a Windows Job Object so timeout,
cancellation, and daemon loss also terminate Harness descendants. The
early-access local threat model still trusts software under the signed-in
Windows user's own Harness installation path; it does not claim binary pinning
or protection from that same user replacing the Harness file.

After installation, open a new PowerShell window so the user environment is
loaded and run:

```powershell
.\bin\egopulse.exe status
.\bin\egopulse.exe work capabilities
.\bin\egopulse-tui.exe
```

The capability list shows Provider, Harness, Harness-model and provider-model
identities separately. Only entries marked `admitted` have a public choice ID
and can start work. Candidate and held entries are diagnostics, not selectable
routes. To start a natural-language work request with the governed default and
Memory retrieval, use:

```powershell
.\bin\egopulse.exe work start --intent 'Summarize this project and propose the next safe change' --scope 'scope:founder' --work-type 'governed_repository_change' --context-ref 'default/README.md' --confirm
```

Place the project's actual `README.md` under
`%LOCALAPPDATA%\EgoPulse\workspaces\default` for this example. A fresh installer
creates this directory and aligns the allowed scope and workspace. Context
references are relative to `codex.workspace_root`; execution takes place under
an isolated detached worktree of the configured repository. Accepting the
result does not merge its patch into the source repository. Existing
configurations are preserved, so use repository setup when upgrading an older
preview rather than changing internal identifiers by hand.

Follow the bundled [repository work loop](docs/engineering/repository-work-loop.md)
to inspect execution approvals, criteria, evidence, explicit Founder decisions
and interrupted submissions.

The TUI exposes the same kernel operation: press `n` to open Work Start, review
the resolved capability and Memory-bound preview, then confirm. Provider output
is projected as a governed stream; CLI and TUI do not call a Harness directly.

The current CLI/TUI package does not contain `egopulse-desktop.exe`. A Desktop
candidate must be built with the explicit `-IncludeDesktop` packaging option
after its native GUI acceptance gate is closed.

## Upgrade and rollback

Before upgrading an existing installation, stop the daemon and preserve its
Authority keys and complete data root (normally `%LOCALAPPDATA%\EgoPulse`) in
an operator-controlled backup. The installer backs up a replaced configuration;
it does not create a complete database/key backup for you.

Configuration v2/v3 migration commands affect JSON only. Authority stores can
migrate when the new daemon opens them, including the Policy V3 expiry ledger.
To return to an older binary, restore its matching pre-upgrade data-root backup
and original keys. Do not open an already migrated store with the old binary
or delete tables to force compatibility.

## Manual first-run setup

Install Windows x64 CPython 3.14 and [uv](https://docs.astral.sh/uv/), then
run this script from the extracted package directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-memory-worker.ps1
```

The setup script uses a package-local `.cache/uv` directory by default, so it
does not depend on permissions for the user's global `uv` cache. Use
`-UvCacheDir` only when an installation policy requires a different writable
cache location.

The script creates the locked Memory/RAG Worker environment under
`workers\memory-rag\.venv`. It does not receive or store an API key.

Copy `config\agentos-config.example.json` to a user-owned data directory,
replace every `replace-*` value, and set the Authority key variables listed in
`config\README.md`. Update `memory_retrieval.worker_executable` to the path
printed by the setup script, keep `working_directory` at the extracted package
root, and keep its `PYTHONPATH` entries pointing at the packaged `src`
directories. The daemon owns the retrieval scope allowlist; clients cannot
broaden it.

Before opening any Authority store, validate the assembled configuration:

```powershell
& .\bin\agentosd.exe --check-config
```

Success reports `stores_opened=false`. A failure exits with code `78` and
reports the first missing or invalid configuration fact; no daemon or business
database is started by this check.

## Start the local product

```powershell
$env:EGOPULSE_USER_CONFIG = 'D:\EgoPulse\data\agentos-config.json'
& .\bin\agentosd.exe
```

In another PowerShell window, use the CLI or TUI:

```powershell
& .\bin\egopulse.exe --help
& .\bin\egopulse.exe memory retrieve --query 'project decision' --scope scope:founder --json
& .\bin\egopulse-tui.exe --once
```

The retrieval path is read-only, deterministic lexical retrieval in this
early-access release. Agent writes remain candidates and require the frozen
Memory governance path for promotion or revocation. Semantic/vector retrieval,
reranking, several production profiles at once, cloud telemetry and enterprise
identity are outside this package. Only the routes the code admits for
production are selectable; Kimi and GLM profiles may be represented as held
candidates, and neither the example configuration nor a held entry grants
production admission.
