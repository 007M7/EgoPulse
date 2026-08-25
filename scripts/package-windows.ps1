param(
    [string]$ArtifactRoot = '.artifacts/release-candidate',
    [string]$CiEvidencePath = '',
    [string]$CiProvider = 'unspecified',
    [string]$CiRun = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot
$env:CI = 'true'
$env:UV_CACHE_DIR = Join-Path $repoRoot '.cache/uv'

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $Command $($Arguments -join ' ')"
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [IO.File]::OpenRead($LiteralPath)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
$cargo = if ($cargoCommand) { $cargoCommand.Path } else { $null }
if (-not $cargo) {
    $rustupCargo = Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'
    if (Test-Path -LiteralPath $rustupCargo) {
        $cargo = $rustupCargo
        $env:PATH = "$(Split-Path -Parent $cargo);$env:PATH"
    }
    else {
        throw 'Rust cargo is missing; install the rust-toolchain.toml toolchain before packaging'
    }
}

$perlCommand = Get-Command perl -ErrorAction SilentlyContinue
if (-not $perlCommand) {
    $strawberryPerl = 'C:\Strawberry\perl\bin\perl.exe'
    if (Test-Path -LiteralPath $strawberryPerl) {
        $env:PATH = "$(Split-Path -Parent $strawberryPerl);$env:PATH"
    }
    else {
        throw 'Perl is required to build vendored OpenSSL for the SQLCipher release candidate'
    }
}

$head = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve the current Git commit' }
$status = @(& git status --porcelain)
if ($status.Count -gt 0) {
    throw 'Windows packaging requires a clean worktree so the candidate maps to one exact commit'
}

$evidence = $null
$resolvedEvidencePath = $null
if (-not [string]::IsNullOrWhiteSpace($CiEvidencePath)) {
    $resolvedEvidencePath = (Resolve-Path -LiteralPath $CiEvidencePath).Path
    $evidence = Get-Content -LiteralPath $resolvedEvidencePath -Raw -Encoding utf8 | ConvertFrom-Json
    if ($evidence.status -ne 'passed' -or $evidence.commit -ne $head -or $evidence.worktree_dirty_at_start) {
        throw 'CI evidence must be successful, clean, and match the exact candidate commit'
    }
}

# Build the frontend assets first, then compile the entire Rust workspace once.
# The Tauri CLI would compile the desktop Rust crate a second time; packaging
# only needs the resulting executable, not a bundled installer.
Invoke-External pnpm --filter '@egopulse/desktop' run build
Invoke-External $cargo build --workspace --release --locked

$version = (Get-Content -LiteralPath 'apps/desktop/src-tauri/tauri.conf.json' -Raw -Encoding utf8 | ConvertFrom-Json).version
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$shortHead = $head.Substring(0, 12)
$candidateName = "egopulse-$version-$shortHead-windows-x86_64-$stamp"
$candidateRoot = Join-Path (Join-Path $repoRoot $ArtifactRoot) $candidateName
$binRoot = Join-Path $candidateRoot 'bin'
$manifestRoot = Join-Path $candidateRoot 'manifests'
New-Item -ItemType Directory -Force -Path $binRoot, $manifestRoot | Out-Null

$binaries = @(
    'agentosd.exe',
    'egopulse.exe',
    'egopulse-tui.exe',
    'egopulse-desktop.exe'
)
foreach ($binary in $binaries) {
    $source = Join-Path $repoRoot "target/release/$binary"
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Expected release binary is missing: $source"
    }
    Copy-Item -LiteralPath $source -Destination $binRoot
}

Copy-Item -LiteralPath 'README.md', 'SECURITY.md' -Destination $candidateRoot
Copy-Item -LiteralPath 'Cargo.lock', 'pnpm-lock.yaml' -Destination $manifestRoot
Copy-Item -LiteralPath 'workers/foundation-probe/uv.lock' -Destination (Join-Path $manifestRoot 'foundation-probe.uv.lock')
Copy-Item -LiteralPath 'workers/contract-bindings/uv.lock' -Destination (Join-Path $manifestRoot 'contract-bindings.uv.lock')
if ($resolvedEvidencePath) {
    Copy-Item -LiteralPath $resolvedEvidencePath -Destination (Join-Path $manifestRoot 'local-ci-evidence.json')
}

$metadata = [ordered]@{
    schema_version = 1
    product = 'EgoPulse'
    version = $version
    commit = $head
    platform = 'windows-x86_64'
    created_at = [DateTimeOffset]::UtcNow.ToString('o')
    classification = 'unsigned-release-candidate'
    ci_provider = $CiProvider
    ci_run = $CiRun
    ci_evidence = if ($resolvedEvidencePath) { 'manifests/local-ci-evidence.json' } else { 'external-workflow' }
}
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $candidateRoot 'BUILD-METADATA.json') -Encoding utf8

$hashLines = Get-ChildItem -LiteralPath $candidateRoot -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($candidateRoot.Length + 1).Replace('\', '/')
        $hash = Get-Sha256Hex -LiteralPath $_.FullName
        "$hash  $relative"
    }
$hashLines | Set-Content -LiteralPath (Join-Path $candidateRoot 'SHA256SUMS') -Encoding ascii

$zipPath = "$candidateRoot.zip"
Compress-Archive -LiteralPath $candidateRoot -DestinationPath $zipPath -CompressionLevel Optimal
$zipHash = Get-Sha256Hex -LiteralPath $zipPath
Set-Content -LiteralPath "$zipPath.sha256" -Value "$zipHash  $([IO.Path]::GetFileName($zipPath))" -Encoding ascii

Write-Output "windows_package=passed classification=unsigned-release-candidate commit=$head ci_provider=$CiProvider"
Write-Output "candidate_directory=$candidateRoot"
Write-Output "candidate_archive=$zipPath"
Write-Output "candidate_sha256=$zipHash"
