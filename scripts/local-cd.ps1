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
$packageOutput = @(& (Join-Path $PSScriptRoot 'package-windows.ps1') `
    -ArtifactRoot $ArtifactRoot `
    -CiEvidencePath $evidencePath `
    -CiProvider 'local')
$packageExitCode = $LASTEXITCODE
$packageOutput | ForEach-Object { Write-Output $_ }
if ($packageExitCode -ne 0) { throw "Windows packaging failed with exit code $packageExitCode" }

$candidateDirectoryLine = $packageOutput |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -like 'candidate_directory=*' } |
    Select-Object -Last 1
$candidateArchiveLine = $packageOutput |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -like 'candidate_archive=*' } |
    Select-Object -Last 1
$candidateSha256Line = $packageOutput |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -like 'candidate_sha256=*' } |
    Select-Object -Last 1
if (-not $candidateDirectoryLine -or -not $candidateArchiveLine -or -not $candidateSha256Line) {
    throw 'Windows packaging did not report a complete candidate identity'
}

$candidateDirectory = $candidateDirectoryLine.Substring('candidate_directory='.Length)
$candidateArchive = $candidateArchiveLine.Substring('candidate_archive='.Length)
$candidateSha256 = $candidateSha256Line.Substring('candidate_sha256='.Length)
& (Join-Path $PSScriptRoot 'verify-windows-package.ps1') `
    -PackageRoot $candidateDirectory `
    -ArchivePath $candidateArchive `
    -ExpectedArchiveSha256 $candidateSha256 `
    -VerifyMemoryWorker
if ($LASTEXITCODE -ne 0) { throw "Windows package verification failed with exit code $LASTEXITCODE" }
