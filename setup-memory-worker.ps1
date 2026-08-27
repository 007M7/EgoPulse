param(
    [string]$PackageRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [string]$UvCacheDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$cacheDir = if ([string]::IsNullOrWhiteSpace($UvCacheDir)) {
    Join-Path $root '.cache/uv'
} else {
    $UvCacheDir
}
$cacheDir = (New-Item -ItemType Directory -Force -Path $cacheDir).FullName
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

${previousUvCacheDir} = $env:UV_CACHE_DIR
try {
    $env:UV_CACHE_DIR = $cacheDir
    & $uvCommand.Path sync --project $memoryProject --frozen
    if ($LASTEXITCODE -ne 0) {
        throw "Memory Worker dependency setup failed with exit code $LASTEXITCODE"
    }
} finally {
    if ($null -eq $previousUvCacheDir) {
        Remove-Item Env:UV_CACHE_DIR -ErrorAction SilentlyContinue
    } else {
        $env:UV_CACHE_DIR = $previousUvCacheDir
    }
}

$python = Join-Path $memoryProject '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw "uv completed without creating the Memory Worker interpreter: $python"
}

Write-Output 'memory_worker_setup=passed'
Write-Output "worker_executable=$python"
Write-Output "working_directory=$root"
Write-Output "uv_cache_directory=$cacheDir"
Write-Output "pythonpath=$(Join-Path $root 'workers/memory-rag/src');$(Join-Path $root 'workers/contract-bindings/src')"
