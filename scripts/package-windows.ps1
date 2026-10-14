param(
    [string]$ArtifactRoot = '.artifacts/release-candidate',
    [string]$CiEvidencePath = '',
    [string]$CiProvider = 'unspecified',
    [string]$CiRun = '',
    [switch]$IncludeDesktop
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'windows-package-integrity.ps1')

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

# Phase 1 ships the shared kernel through agentosd, CLI and TUI. Desktop is a
# later vertical; keep an explicit opt-in for a future desktop candidate so
# the first release does not accidentally claim desktop feature completeness.
$cargoArguments = @(
    'build',
    '--release',
    '--locked',
    '-p', 'egopulse-agentosd',
    '-p', 'egopulse-cli',
    '-p', 'egopulse-tui'
)
if ($IncludeDesktop) {
    Invoke-External pnpm --filter '@egopulse/desktop' run build
    $cargoArguments += @('-p', 'egopulse-desktop')
}
Invoke-External $cargo @cargoArguments

$version = (Get-Content -LiteralPath 'apps/desktop/src-tauri/tauri.conf.json' -Raw -Encoding utf8 | ConvertFrom-Json).version
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$shortHead = $head.Substring(0, 12)
$candidateName = "egopulse-$version-$shortHead-windows-x86_64-$stamp"
$artifactDirectory = Join-Path $repoRoot $ArtifactRoot
$null = New-Item -ItemType Directory -Force -Path $artifactDirectory
$candidateRoot = Join-Path $artifactDirectory $candidateName
$zipPath = "$candidateRoot.zip"
$zipHashPath = "$zipPath.sha256"
foreach ($target in @($candidateRoot, $zipPath, $zipHashPath)) {
    if (Test-Path -LiteralPath $target) {
        throw "Windows package target already exists: $target"
    }
}
$binRoot = Join-Path $candidateRoot 'bin'
$manifestRoot = Join-Path $candidateRoot 'manifests'
$null = New-EgoPulseExclusiveDirectory -LiteralPath $candidateRoot
$null = New-EgoPulseExclusiveDirectory -LiteralPath $binRoot
$null = New-EgoPulseExclusiveDirectory -LiteralPath $manifestRoot

$binaries = @(
    'agentosd.exe',
    'egopulse.exe',
    'egopulse-tui.exe'
)
if ($IncludeDesktop) {
    $binaries += 'egopulse-desktop.exe'
}
foreach ($binary in $binaries) {
    $source = Join-Path $repoRoot "target/release/$binary"
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Expected release binary is missing: $source"
    }
    Copy-EgoPulseFileExclusively -SourcePath $source -DestinationPath (Join-Path $binRoot $binary)
}

foreach ($source in @('README.md', 'SECURITY.md', 'WINDOWS-EARLY-ACCESS.md', 'setup-memory-worker.ps1', 'install-egopulse.ps1', 'egopulse-keys.ps1')) {
    Copy-EgoPulseFileExclusively -SourcePath $source -DestinationPath (Join-Path $candidateRoot (Split-Path -Leaf $source))
}
$configRoot = Join-Path $candidateRoot 'config'
$null = New-EgoPulseExclusiveDirectory -LiteralPath $configRoot
foreach ($source in @(
    'config/agentos-config.example.json',
    'config/README.md',
    'config/artifact-authority.md',
    'config/memory-authority.md',
    'config/verification-worker.example.json'
)) {
    Copy-EgoPulseFileExclusively -SourcePath $source -DestinationPath (Join-Path $configRoot (Split-Path -Leaf $source))
}
foreach ($source in @('Cargo.lock', 'pnpm-lock.yaml')) {
    Copy-EgoPulseFileExclusively -SourcePath $source -DestinationPath (Join-Path $manifestRoot (Split-Path -Leaf $source))
}
$operatorDocsRoot = Join-Path $candidateRoot 'docs/engineering'
$null = New-Item -ItemType Directory -Path $operatorDocsRoot
Copy-EgoPulseFileExclusively -SourcePath 'docs/engineering/repository-work-loop.md' -DestinationPath (Join-Path $operatorDocsRoot 'repository-work-loop.md')
Copy-EgoPulseFileExclusively -SourcePath 'docs/engineering/local-key-recovery.md' -DestinationPath (Join-Path $operatorDocsRoot 'local-key-recovery.md')
Copy-EgoPulseFileExclusively -SourcePath 'workers/foundation-probe/uv.lock' -DestinationPath (Join-Path $manifestRoot 'foundation-probe.uv.lock')
Copy-EgoPulseFileExclusively -SourcePath 'workers/contract-bindings/uv.lock' -DestinationPath (Join-Path $manifestRoot 'contract-bindings.uv.lock')

# Memory retrieval is part of the first CLI/TUI release. Ship the locked,
# read-only Worker source and generated Python contract consumer beside the
# binaries; the end user's CPython/uv installation creates the isolated .venv.
$workersRoot = Join-Path $candidateRoot 'workers'
$null = New-EgoPulseExclusiveDirectory -LiteralPath $workersRoot
foreach ($workerName in @('memory-rag', 'contract-bindings')) {
    $workerRoot = Join-Path $workersRoot $workerName
    $null = New-EgoPulseExclusiveDirectory -LiteralPath $workerRoot
    foreach ($source in @("workers/$workerName/pyproject.toml", "workers/$workerName/uv.lock")) {
        Copy-EgoPulseFileExclusively -SourcePath $source -DestinationPath (Join-Path $workerRoot (Split-Path -Leaf $source))
    }
    $null = Copy-EgoPulsePublicTreeExclusively `
        -SourceRoot "workers/$workerName/src" `
        -DestinationRoot (Join-Path $workerRoot 'src')
}
if ($resolvedEvidencePath) {
    Copy-EgoPulseFileExclusively -SourcePath $resolvedEvidencePath -DestinationPath (Join-Path $manifestRoot 'local-ci-evidence.json')
}

$metadata = [ordered]@{
    schema_version = 1
    product = 'EgoPulse'
    version = $version
    commit = $head
    platform = 'windows-x86_64'
    surfaces = if ($IncludeDesktop) { @('cli', 'tui', 'desktop') } else { @('cli', 'tui') }
    created_at = [DateTimeOffset]::UtcNow.ToString('o')
    classification = 'unsigned-release-candidate'
    ci_provider = $CiProvider
    ci_run = $CiRun
    ci_evidence = if ($resolvedEvidencePath) { 'manifests/local-ci-evidence.json' } else { 'external-workflow' }
    memory_worker = 'packaged-source-locked-python'
    python_runtime = 'external-cpython-3.14-and-uv'
}
Write-EgoPulseTextFileExclusively `
    -LiteralPath (Join-Path $candidateRoot 'BUILD-METADATA.json') `
    -Value (($metadata | ConvertTo-Json -Depth 5) + [Environment]::NewLine) `
    -Encoding ([Text.UTF8Encoding]::new($false))

$packageInventory = @(Get-EgoPulsePackageFileInventory -PackageRoot $candidateRoot)
$hashLines = $packageInventory |
    ForEach-Object {
        $hash = Get-EgoPulseSha256Hex -LiteralPath $_.FullPath
        "$hash  $($_.Path)"
    }
Write-EgoPulseTextFileExclusively `
    -LiteralPath (Join-Path $candidateRoot 'SHA256SUMS') `
    -Value (($hashLines -join [Environment]::NewLine) + [Environment]::NewLine) `
    -Encoding ([Text.Encoding]::ASCII)
$null = Test-EgoPulsePackageManifest -PackageRoot $candidateRoot -RequiredFiles @(
    'config/agentos-config.example.json'
)

$null = New-EgoPulsePackageArchiveExclusively -PackageRoot $candidateRoot -ArchivePath $zipPath
$zipHash = Get-EgoPulseSha256Hex -LiteralPath $zipPath
Write-EgoPulseTextFileExclusively `
    -LiteralPath $zipHashPath `
    -Value ("$zipHash  $([IO.Path]::GetFileName($zipPath))" + [Environment]::NewLine) `
    -Encoding ([Text.Encoding]::ASCII)

Write-Output "windows_package=passed classification=unsigned-release-candidate commit=$head ci_provider=$CiProvider"
Write-Output "candidate_directory=$candidateRoot"
Write-Output "candidate_archive=$zipPath"
Write-Output "candidate_sha256=$zipHash"
