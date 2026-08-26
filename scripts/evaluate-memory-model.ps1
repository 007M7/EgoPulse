param(
    [Parameter(Mandatory = $true)]
    [string]$DatasetPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("paraphrase-multilingual-minilm-v0", "multilingual-e5-small-v0")]
    [string]$Model,

    [ValidateRange(1, 256)]
    [int]$Threads = 4,

    [ValidateRange(1, 64)]
    [int]$K = 2,

    [ValidateRange(0.01, 100.0)]
    [double]$LexicalWeight = 1.0,

    [ValidateRange(0.01, 100.0)]
    [double]$SemanticWeight = 1.0,

    [switch]$AllowDownload
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$workerRoot = Join-Path $repoRoot "workers\memory-rag"
$contractBindings = Join-Path $repoRoot "workers\contract-bindings\src"
$workerSource = Join-Path $workerRoot "src"
$modelCache = Join-Path $repoRoot ".cache\fastembed"
$env:UV_CACHE_DIR = Join-Path $repoRoot ".cache\uv"
$env:PYTHONPATH = "$workerSource;$contractBindings"

$arguments = @(
    "run",
    "--project", $workerRoot,
    "--frozen",
    "--group", "evaluation",
    "python", "-m", "egopulse_memory_rag.model_evaluation",
    "--dataset", (Join-Path $repoRoot $DatasetPath),
    "--model", $Model,
    "--cache-dir", $modelCache,
    "--threads", $Threads,
    "--k", $K,
    "--lexical-weight", $LexicalWeight,
    "--semantic-weight", $SemanticWeight
)
if (-not $AllowDownload) {
    $arguments += "--local-files-only"
}

& uv @arguments
exit $LASTEXITCODE
