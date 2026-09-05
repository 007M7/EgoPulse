param(
    [switch]$SkipCi,
    [string]$ArtifactRoot = '.artifacts/release-candidate'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'windows-package-integrity.ps1')

function Get-ExactCandidateIdentity {
    param(
        [Parameter(Mandatory = $true)][object[]]$Output,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $matches = @($Output |
        ForEach-Object { [string]$_ } |
        Where-Object { $_.StartsWith($Prefix, [StringComparison]::Ordinal) })
    if ($matches.Count -ne 1) {
        throw "Windows packaging must report exactly one ${Prefix} identity line; found $($matches.Count)"
    }
    $value = $matches[0].Substring($Prefix.Length)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Windows packaging reported an empty ${Prefix} identity value"
    }
    return $value
}

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

$candidateDirectory = Get-ExactCandidateIdentity -Output $packageOutput -Prefix 'candidate_directory='
$candidateArchive = Get-ExactCandidateIdentity -Output $packageOutput -Prefix 'candidate_archive='
$candidateSha256 = Get-ExactCandidateIdentity -Output $packageOutput -Prefix 'candidate_sha256='
$null = Assert-EgoPulseArchiveArguments -ArchivePath $candidateArchive -ExpectedArchiveSha256 $candidateSha256
& (Join-Path $PSScriptRoot 'verify-windows-package.ps1') `
    -PackageRoot $candidateDirectory `
    -ArchivePath $candidateArchive `
    -ExpectedArchiveSha256 $candidateSha256 `
    -VerifyMemoryWorker
if ($LASTEXITCODE -ne 0) { throw "Windows package verification failed with exit code $LASTEXITCODE" }
