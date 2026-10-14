param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [string]$ArchivePath,
    [string]$ExpectedArchiveSha256,
    [switch]$VerifyMemoryWorker
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'windows-package-integrity.ps1')

$archiveMode = Assert-EgoPulseArchiveArguments -ArchivePath $ArchivePath -ExpectedArchiveSha256 $ExpectedArchiveSha256
if ($VerifyMemoryWorker -and -not $archiveMode) {
    throw 'VerifyMemoryWorker requires ArchivePath so worker state remains inside the temporary extraction root.'
}

$requiredFiles = @(
    'bin/agentosd.exe',
    'bin/egopulse.exe',
    'bin/egopulse-tui.exe',
    'BUILD-METADATA.json',
    'SHA256SUMS',
    'setup-memory-worker.ps1',
    'install-egopulse.ps1',
    'egopulse-keys.ps1',
    'config/agentos-config.example.json',
    'config/README.md',
    'docs/engineering/repository-work-loop.md',
    'docs/engineering/local-key-recovery.md',
    'workers/memory-rag/pyproject.toml',
    'workers/memory-rag/uv.lock',
    'workers/contract-bindings/pyproject.toml',
    'workers/contract-bindings/uv.lock'
)
$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$sourceManifest = Test-EgoPulsePackageManifest -PackageRoot $root -RequiredFiles $requiredFiles
$metadataPath = Join-Path $root 'BUILD-METADATA.json'
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
if (@($metadata.surfaces) -contains 'desktop') {
    $desktopBinary = Join-Path $root 'bin/egopulse-desktop.exe'
    if (-not (Test-Path -LiteralPath $desktopBinary -PathType Leaf)) {
        throw 'Package metadata declares Desktop but egopulse-desktop.exe is missing'
    }
    $desktopLength = (Get-Item -LiteralPath $desktopBinary).Length
    if ($desktopLength -le 0) {
        throw 'Desktop binary is empty'
    }
    Write-Output "egopulse-desktop.exe_present=passed size=$desktopLength"
}

$extraction = $null
try {
    $executionRoot = $root
    if ($archiveMode) {
        $topLevel = Split-Path -Leaf $root.TrimEnd('\', '/')
        $extraction = Expand-EgoPulseArchiveSafely `
            -ArchivePath $ArchivePath `
            -ExpectedArchiveSha256 $ExpectedArchiveSha256 `
            -ExpectedTopLevel $topLevel
        Compare-EgoPulsePackageTrees -SourceRoot $root -ExtractedRoot $extraction.PackageRoot
        $executionRoot = $extraction.PackageRoot
        Write-Output "archive_sha256=$($extraction.ArchiveSha256)"
    }

    Invoke-EgoPulseRestoredEnvironment {
        foreach ($executable in @('egopulse.exe', 'egopulse-tui.exe', 'agentosd.exe')) {
            $helpOutput = @(& (Join-Path $executionRoot "bin/$executable") --help 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "$executable --help failed with exit code $LASTEXITCODE"
            }
            if ($executable -eq 'agentosd.exe' -and (($helpOutput -join [Environment]::NewLine) -notmatch [regex]::Escape('--prepare-repository-config'))) {
                throw 'agentosd.exe does not expose the packaged repository configuration candidate command'
            }
            Write-Output "${executable}_help=passed"
        }

        $installerPath = Join-Path $executionRoot 'install-egopulse.ps1'
        $installerTokens = $null
        $installerParseErrors = $null
        $installerAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $installerPath,
            [ref]$installerTokens,
            [ref]$installerParseErrors
        )
        if ($installerParseErrors.Count -gt 0) {
            throw "Packaged installer has PowerShell parse errors: $($installerParseErrors[0].Message)"
        }
        $installerParameters = @($installerAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        foreach ($parameterName in @('RepositoryRoot', 'AcceptanceContractPath', 'GitExecutable', 'ReviewModel')) {
            if ($installerParameters -notcontains $parameterName) {
                throw "Packaged installer is missing repository setup parameter: $parameterName"
            }
        }
        $installerSource = Get-Content -LiteralPath $installerPath -Raw -Encoding utf8
        if ($installerSource -notmatch [regex]::Escape('--prepare-repository-config')) {
            throw 'Packaged installer does not prepare repository configuration candidates'
        }
        Write-Output 'repository_setup_package_surface=passed'

        & (Join-Path $executionRoot 'bin/egopulse-tui.exe') --foundation-check *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "egopulse-tui.exe --foundation-check failed with exit code $LASTEXITCODE"
        }
        Write-Output 'egopulse-tui_foundation_check=passed'

        $env:EGOPULSE_USER_CONFIG = Join-Path $executionRoot '.verification-missing-config.json'
        $probeErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & (Join-Path $executionRoot 'bin/agentosd.exe') --check-config 2>$null *> $null
            $probeExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $probeErrorAction
        }
        if ($probeExitCode -ne 78) {
            throw "agentosd.exe --check-config expected fail-closed exit code 78, got $probeExitCode"
        }
        Write-Output 'agentosd_missing_config_fail_closed=passed'

        if ($VerifyMemoryWorker) {
            $uvCacheDir = Join-Path $executionRoot '.cache/uv'
            & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $executionRoot 'setup-memory-worker.ps1') -PackageRoot $executionRoot -UvCacheDir $uvCacheDir
            if ($LASTEXITCODE -ne 0) {
                throw "Packaged Memory Worker setup failed with exit code $LASTEXITCODE"
            }
            $python = Join-Path $executionRoot 'workers/memory-rag/.venv/Scripts/python.exe'
            $env:PYTHONPATH = (Join-Path $executionRoot 'workers/memory-rag/src') + ';' +
                (Join-Path $executionRoot 'workers/contract-bindings/src')
            & $python -c "import importlib.util; import egopulse_memory_rag.retrieval; assert importlib.util.find_spec('fastembed') is None"
            if ($LASTEXITCODE -ne 0) {
                throw 'Production Memory Worker import or evaluation-dependency exclusion failed'
            }
            Write-Output 'memory_worker_production_profile=passed'
        }
    }

    Write-Output "windows_package_verification=passed files=$($sourceManifest.Entries.Count)"
}
finally {
    if ($extraction) {
        Remove-EgoPulseVerificationTemporaryRoot -TemporaryRoot $extraction.TemporaryRoot
    }
}
