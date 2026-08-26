param(
    [string]$PackageRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$memoryProject = Join-Path $root 'workers/memory-rag'
$bindingsProject = Join-Path $root 'workers/contract-bindings'
foreach ($project in @($memoryProject, $bindingsProject)) {
    if (-not (Test-Path -LiteralPath (Join-Path $project 'pyproject.toml'))) {
        throw "Packaged Python project is missing: $project"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $project 'uv.lock'))) {
        throw "Packaged Python lockfile is missing: $project"
    }
}

$uvCommand = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uvCommand) {
    throw 'uv is required. Install uv and rerun setup-memory-worker.ps1.'
}

& $uvCommand.Path sync --project $memoryProject --frozen
if ($LASTEXITCODE -ne 0) {
    throw "Memory Worker dependency setup failed with exit code $LASTEXITCODE"
}

$python = Join-Path $memoryProject '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw "uv completed without creating the Memory Worker interpreter: $python"
}

Write-Output 'memory_worker_setup=passed'
Write-Output "worker_executable=$python"
Write-Output "working_directory=$root"
Write-Output "pythonpath=$(Join-Path $root 'workers/memory-rag/src');$(Join-Path $root 'workers/contract-bindings/src')"
