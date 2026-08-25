param(
    [switch]$SkipCi,
    [string]$ArtifactRoot = '.artifacts/release-candidate'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot
$env:CI = 'true'
$env:UV_CACHE_DIR = Join-Path $repoRoot '.cache/uv'

if (-not $SkipCi) {
    & (Join-Path $PSScriptRoot 'local-ci.ps1')
    if ($LASTEXITCODE -ne 0) { throw "Local CI failed with exit code $LASTEXITCODE" }
}

$evidencePath = Join-Path $repoRoot '.local-ci/evidence/latest.json'
if (-not (Test-Path -LiteralPath $evidencePath)) {
    throw 'Local CI evidence is missing; run scripts/local-ci.ps1 first'
}
& (Join-Path $PSScriptRoot 'package-windows.ps1') `
    -ArtifactRoot $ArtifactRoot `
    -CiEvidencePath $evidencePath `
    -CiProvider 'local'
if ($LASTEXITCODE -ne 0) { throw "Windows packaging failed with exit code $LASTEXITCODE" }
