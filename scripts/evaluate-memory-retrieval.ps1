param(
    [string]$DatasetPath,
    [ValidateRange(1, 64)]
    [int]$K = 8
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$workerRoot = Join-Path $repositoryRoot 'workers\memory-rag'
$workerSource = Join-Path $workerRoot 'src'
$contractSource = Join-Path $repositoryRoot 'workers\contract-bindings\src'
if ([string]::IsNullOrWhiteSpace($DatasetPath)) {
    $DatasetPath = Join-Path $workerRoot 'evaluation\baseline-v0.json'
}
$resolvedDataset = (Resolve-Path -LiteralPath $DatasetPath).Path

$env:UV_CACHE_DIR = Join-Path $repositoryRoot '.cache\uv'
$env:PYTHONPATH = "$workerSource;$contractSource"

& uv run --project $workerRoot --frozen python -m egopulse_memory_rag.evaluation `
    --dataset $resolvedDataset `
    --k $K
if ($LASTEXITCODE -ne 0) {
    throw "Memory retrieval evaluation failed with exit code $LASTEXITCODE"
}
