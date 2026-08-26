# Windows x64 early access

This package is the first CLI/TUI release of EgoPulse. The CLI, TUI and
`agentosd.exe` use the same Rust control kernel and local IPC transport. The
Desktop/Tauri surface is not part of phase one.

The package is intentionally **unsigned**. Windows SmartScreen may show an
unknown-publisher warning. Verify the downloaded archive with the adjacent
`.sha256` file before extracting it; the package also contains `SHA256SUMS`
for per-file verification. Do not treat an unsigned candidate as a production
release.

## First-run setup

Install Windows x64 CPython 3.14 and [uv](https://docs.astral.sh/uv/), then
run this script from the extracted package directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-memory-worker.ps1
```

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
reranking, a second production Harness, cloud telemetry and enterprise
identity are outside this package.
