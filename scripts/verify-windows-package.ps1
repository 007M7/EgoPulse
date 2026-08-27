param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [string]$ArchivePath,
    [string]$ExpectedArchiveSha256,
    [switch]$VerifyMemoryWorker
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$metadataPath = Join-Path $root 'BUILD-METADATA.json'
$sumsPath = Join-Path $root 'SHA256SUMS'
$requiredFiles = @(
    'bin/agentosd.exe',
    'bin/egopulse.exe',
    'bin/egopulse-tui.exe',
    'BUILD-METADATA.json',
    'SHA256SUMS',
    'setup-memory-worker.ps1',
    'install-egopulse.ps1',
    'workers/memory-rag/pyproject.toml',
    'workers/memory-rag/uv.lock',
    'workers/contract-bindings/pyproject.toml',
    'workers/contract-bindings/uv.lock'
)

foreach ($relativePath in $requiredFiles) {
    $path = Join-Path $root ($relativePath -replace '/', '\')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required package file is missing: $relativePath"
    }
}

$metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
if ($metadata.classification -ne 'unsigned-release-candidate') {
    throw "Unexpected package classification: $($metadata.classification)"
}
if ($metadata.platform -ne 'windows-x86_64') {
    throw "Unexpected package platform: $($metadata.platform)"
}
if (@($metadata.surfaces) -notcontains 'cli' -or @($metadata.surfaces) -notcontains 'tui') {
    throw 'Package metadata must declare both CLI and TUI surfaces'
}

$sumLines = Get-Content -LiteralPath $sumsPath | Where-Object { $_.Trim() -ne '' }
if ($sumLines.Count -eq 0) {
    throw 'SHA256SUMS is empty'
}
foreach ($line in $sumLines) {
    if ($line -notmatch '^([0-9a-fA-F]{64})\s+(.+)$') {
        throw "Malformed SHA256SUMS line: $line"
    }
    $expected = $Matches[1].ToLowerInvariant()
    $relativePath = $Matches[2].Trim() -replace '/', '\'
    $path = Join-Path $root $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "SHA256SUMS references missing file: $relativePath"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch for ${relativePath}: expected $expected, got $actual"
    }
}

if ($ArchivePath) {
    $archive = (Resolve-Path -LiteralPath $ArchivePath).Path
    $archiveSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($ExpectedArchiveSha256 -and $archiveSha256 -ne $ExpectedArchiveSha256.ToLowerInvariant()) {
        throw "Archive SHA-256 mismatch: expected $ExpectedArchiveSha256, got $archiveSha256"
    }
    Write-Output "archive_sha256=$archiveSha256"
}

foreach ($executable in @('egopulse.exe', 'egopulse-tui.exe', 'agentosd.exe')) {
    & (Join-Path $root "bin/$executable") --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "$executable --help failed with exit code $LASTEXITCODE"
    }
    Write-Output "${executable}_help=passed"
}

# These probes exercise the two safe, non-daemon startup paths shipped in the
# first package. TUI must be able to report its local foundation state without
# entering raw terminal mode. The daemon must fail closed when no user-owned
# configuration is present; a package verifier must never accidentally pass by
# consuming a developer's ambient EGOPULSE_USER_CONFIG.
& (Join-Path $root 'bin/egopulse-tui.exe') --foundation-check *> $null
if ($LASTEXITCODE -ne 0) {
    throw "egopulse-tui.exe --foundation-check failed with exit code $LASTEXITCODE"
}
Write-Output 'egopulse-tui_foundation_check=passed'

$previousUserConfig = $env:EGOPULSE_USER_CONFIG
try {
    $env:EGOPULSE_USER_CONFIG = Join-Path $root '.verification-missing-config.json'
    $probeErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell promotes native stderr to a non-terminating
        # NativeCommandError under Stop. Continue only for this intentional
        # refusal, then assert the native process exit code explicitly.
        $ErrorActionPreference = 'Continue'
        & (Join-Path $root 'bin/agentosd.exe') --check-config 2>$null *> $null
        $probeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $probeErrorAction
    }
    if ($probeExitCode -ne 78) {
        throw "agentosd.exe --check-config expected fail-closed exit code 78, got $probeExitCode"
    }
    Write-Output 'agentosd_missing_config_fail_closed=passed'
}
finally {
    if ($null -eq $previousUserConfig) {
        Remove-Item Env:EGOPULSE_USER_CONFIG -ErrorAction SilentlyContinue
    }
    else {
        $env:EGOPULSE_USER_CONFIG = $previousUserConfig
    }
}

if ($VerifyMemoryWorker) {
    $uvCacheDir = Join-Path $root '.cache/uv'
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'setup-memory-worker.ps1') -PackageRoot $root -UvCacheDir $uvCacheDir
    if ($LASTEXITCODE -ne 0) {
        throw "Packaged Memory Worker setup failed with exit code $LASTEXITCODE"
    }
    $python = Join-Path $root 'workers/memory-rag/.venv/Scripts/python.exe'
    $env:PYTHONPATH = (Join-Path $root 'workers/memory-rag/src') + ';' +
        (Join-Path $root 'workers/contract-bindings/src')
    & $python -c "import importlib.util; import egopulse_memory_rag.retrieval; assert importlib.util.find_spec('fastembed') is None"
    if ($LASTEXITCODE -ne 0) {
        throw 'Production Memory Worker import or evaluation-dependency exclusion failed'
    }
    Write-Output 'memory_worker_production_profile=passed'
}

Write-Output "windows_package_verification=passed files=$($sumLines.Count)"
