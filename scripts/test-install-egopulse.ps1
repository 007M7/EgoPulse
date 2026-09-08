param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-EgoPulseEnvironmentSnapshot {
    param([Parameter(Mandatory = $true)][EnvironmentVariableTarget]$Target)

    $entries = [Environment]::GetEnvironmentVariables($Target).GetEnumerator() |
        Where-Object { [string]$_.Key -like 'EGOPULSE_*' } |
        Sort-Object { [string]$_.Key } |
        ForEach-Object { '{0}={1}' -f [string]$_.Key, [string]$_.Value }
    return ($entries -join "`n")
}

function Restore-EgoPulseProcessEnvironment {
    param([Parameter(Mandatory = $true)][hashtable]$Snapshot)

    foreach ($entry in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        $name = [string]$entry
        if ($name -like 'EGOPULSE_*') {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
    foreach ($entry in $Snapshot.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, 'Process')
    }
}

function ConvertTo-SingleQuotedPowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)

    return "'$($Value.Replace("'", "''"))'"
}

function Invoke-HermeticInstaller {
    param(
        [Parameter(Mandatory = $true)][string]$InstallerPath,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][string]$IpcInstance
    )

    $keyLiterals = ($authorityKeys | ForEach-Object { ConvertTo-SingleQuotedPowerShellLiteral $_ }) -join ','
    $command = @"
if (Get-Command uv -ErrorAction SilentlyContinue) { throw 'uv unexpectedly visible in hermetic installer child' }
Write-Output 'uv=unavailable'
& $(ConvertTo-SingleQuotedPowerShellLiteral $InstallerPath) -PackageRoot $(ConvertTo-SingleQuotedPowerShellLiteral $PackageRoot) -DataRoot $(ConvertTo-SingleQuotedPowerShellLiteral $DataRoot) -IpcInstance $(ConvertTo-SingleQuotedPowerShellLiteral $IpcInstance) -SkipMemoryWorker -NoPersistEnvironment
foreach (`$keyName in @($keyLiterals)) {
    if ([Environment]::GetEnvironmentVariable(`$keyName, 'Process') -cne `$env:EGOPULSE_INSTALLER_TEST_KEY_SENTINEL) {
        throw "process-only Authority key changed: `$keyName"
    }
}
Write-Output 'process_authority_keys=preserved'
"@
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $powershellPath = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $powershellPath
    $startInfo.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    Assert-Condition $process.Start() 'failed to start hermetic installer child process'
    $stdoutRead = $process.StandardOutput.ReadToEndAsync()
    $stderrRead = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) {
        try { $process.Kill() } catch {}
        $null = $process.WaitForExit(10000)
        throw 'hermetic installer child exceeded the 60 second timeout'
    }
    $process.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdoutRead.GetAwaiter().GetResult()
        Stderr = $stderrRead.GetAwaiter().GetResult()
    }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$debugRoot = Join-Path $repositoryRoot 'target/debug'
$requiredBinaries = @('agentosd.exe', 'egopulse.exe', 'egopulse-tui.exe')
foreach ($binary in $requiredBinaries) {
    $binaryPath = Join-Path $debugRoot $binary
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "Required debug binary is missing: $binaryPath. Build the debug CLI, TUI, and daemon before running this test."
    }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox = Join-Path $tempBase "egopulse-installer-test-$([Guid]::NewGuid().ToString('N'))"
$packageRoot = Join-Path $sandbox 'package'
$dataRoot = Join-Path $sandbox 'data'
$invalidDataRoot = Join-Path $sandbox 'invalid-data'
$ipcInstance = "installer-test-$([Guid]::NewGuid().ToString('N'))"
$keySentinel = ('19' * 32)
$authorityKeys = @(
    'EGOPULSE_TASK_KEY_HEX',
    'EGOPULSE_MEMORY_KEY_HEX',
    'EGOPULSE_ARTIFACT_KEY_HEX',
    'EGOPULSE_VERIFICATION_KEY_HEX',
    'EGOPULSE_POLICY_KEY_HEX',
    'EGOPULSE_VERDICT_KEY_HEX',
    'EGOPULSE_ADAPTER_KEY_HEX',
    'EGOPULSE_COLLABORATION_KEY_HEX',
    'EGOPULSE_READ_MODEL_KEY_HEX',
    'EGOPULSE_TOKEN_MAC_KEY_HEX'
)
$parentPath = $env:PATH
$processSnapshot = @{}
foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
    if ([string]$entry.Key -like 'EGOPULSE_*') {
        $processSnapshot[[string]$entry.Key] = [string]$entry.Value
    }
}
$userEnvironmentBefore = Get-EgoPulseEnvironmentSnapshot -Target User

try {
    $env:PATH = "$(Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0');$(Join-Path $env:SystemRoot 'System32')"
    foreach ($keyName in $authorityKeys) {
        Set-Item -Path "Env:$keyName" -Value $keySentinel
    }
    Set-Item -Path 'Env:EGOPULSE_INSTALLER_TEST_KEY_SENTINEL' -Value $keySentinel
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $packageRoot 'bin')
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $packageRoot 'config')
    $harnessBin = (New-Item -ItemType Directory -Force -Path (Join-Path $sandbox 'harness-bin')).FullName
    foreach ($binary in $requiredBinaries) {
        Copy-Item -LiteralPath (Join-Path $debugRoot $binary) -Destination (Join-Path $packageRoot "bin/$binary")
    }
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'config/agentos-config.example.json') -Destination (Join-Path $packageRoot 'config/agentos-config.example.json')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'install-egopulse.ps1') -Destination (Join-Path $packageRoot 'install-egopulse.ps1')
    $installerPath = Join-Path $packageRoot 'install-egopulse.ps1'

    $invalid = Invoke-HermeticInstaller -InstallerPath $installerPath -PackageRoot $packageRoot -DataRoot $invalidDataRoot -IpcInstance 'bad/instance'
    Assert-Condition ($invalid.ExitCode -ne 0) 'invalid IpcInstance unexpectedly succeeded'
    Assert-Condition (-not (Test-Path -LiteralPath $invalidDataRoot)) 'invalid IpcInstance wrote DataRoot before validation failed'

    $missingHarness = Invoke-HermeticInstaller -InstallerPath $installerPath -PackageRoot $packageRoot -DataRoot $dataRoot -IpcInstance $ipcInstance
    Assert-Condition ($missingHarness.ExitCode -ne 0) 'installer unexpectedly accepted a missing production Harness'
    Assert-Condition (-not $missingHarness.Stdout.Contains('egopulse_installation=passed')) 'missing production Harness emitted the installer success marker'
    Assert-Condition (($missingHarness.Stdout + $missingHarness.Stderr).Contains('Production Harness executable is unavailable')) 'missing production Harness failure was not actionable'

    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32/where.exe') -Destination (Join-Path $harnessBin 'codex.exe')
    $env:PATH = "$harnessBin;$env:PATH"
    $result = Invoke-HermeticInstaller -InstallerPath $installerPath -PackageRoot $packageRoot -DataRoot $dataRoot -IpcInstance $ipcInstance
    Assert-Condition ($result.ExitCode -eq 0) "installer failed: stdout=$($result.Stdout) stderr=$($result.Stderr)"
    Assert-Condition ($result.Stdout.Contains('agentosd configuration=passed stores_opened=false')) 'daemon configuration check success was not observed'
    Assert-Condition ($result.Stdout.Contains('uv=unavailable')) 'hermetic child did not prove uv was unavailable'
    Assert-Condition ($result.Stdout.Contains('process_authority_keys=preserved')) 'NoPersistEnvironment did not preserve inherited process-only Authority keys'
    Assert-Condition ($result.Stdout.Contains('egopulse_installation=passed')) 'installer success marker is missing'
    Assert-Condition ($result.Stdout.Contains('production_provider_preflight=ready')) 'production Harness readiness was not enforced'
    Assert-Condition ($result.Stdout.Contains('environment=process-only')) 'process-only environment mode was not reported'
    Assert-Condition ($result.Stdout.Contains("ipc_instance=$ipcInstance")) 'requested IPC instance was not reported'
    Assert-Condition (-not $result.Stdout.Contains($keySentinel)) 'installer stdout leaked an authority key sentinel'
    Assert-Condition (-not $result.Stderr.Contains($keySentinel)) 'installer stderr leaked an authority key sentinel'
    Assert-Condition ($result.Stdout.Contains('Process-only values are not persisted beyond the installer process')) 'process-only lifetime guidance is missing'

    $configPath = Join-Path $dataRoot 'agentos-config.json'
    Assert-Condition (Test-Path -LiteralPath $configPath -PathType Leaf) 'generated configuration is missing from DataRoot'
    $installedConfig = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Condition (@($installedConfig.founder.non_overridable_gate_ids).Count -eq 0) 'new installation retained development-stage gates as permanent task blockers'
    Assert-Condition (@($installedConfig.founder.non_overridable_criterion_ids).Count -eq 1 -and $installedConfig.founder.non_overridable_criterion_ids[0] -eq 'scope') 'new installation omitted the evidence-based scope gate'
    Assert-Condition ($installedConfig.task_guard.allowed_target_scope_refs -contains 'scope:founder') 'installed task scope is not available to the Founder'
    Assert-Condition ($installedConfig.artifact.allowed_workspace_refs -contains $installedConfig.codex.workflow.workspace_ref) 'Artifact and Harness workspace bindings differ'
    Assert-Condition (Test-Path -LiteralPath (Join-Path $installedConfig.codex.workspace_root $installedConfig.codex.workflow.workspace_ref) -PathType Container) 'installed Harness workspace does not resolve to an existing directory'
    $generatedConfigs = @(Get-ChildItem -LiteralPath $sandbox -Recurse -File -Filter 'agentos-config.json')
    Assert-Condition ($generatedConfigs.Count -eq 1) 'generated configuration exists outside the unique DataRoot'
    Assert-Condition ($generatedConfigs[0].FullName -eq (Get-Item -LiteralPath $configPath).FullName) 'generated configuration path is not the unique DataRoot'
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $packageRoot '.cache'))) 'SkipMemoryWorker created a package worker cache'
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $packageRoot 'workers/memory-rag/.venv'))) 'SkipMemoryWorker created a Memory Worker virtual environment'

    $userEnvironmentAfter = Get-EgoPulseEnvironmentSnapshot -Target User
    Assert-Condition ($userEnvironmentAfter -ceq $userEnvironmentBefore) 'NoPersistEnvironment changed User-scope EGOPULSE environment variables'
    Write-Output "installer_hermetic_test=passed ipc_instance=$ipcInstance"
}
finally {
    $env:PATH = $parentPath
    Restore-EgoPulseProcessEnvironment -Snapshot $processSnapshot
    if (Test-Path -LiteralPath $sandbox) {
        $resolvedSandbox = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $sandbox).Path).TrimEnd('\')
        $expectedPrefix = "$tempBase\egopulse-installer-test-"
        if (-not $resolvedSandbox.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to remove unexpected installer test root: $resolvedSandbox"
        }
        Remove-Item -LiteralPath $resolvedSandbox -Recurse -Force
    }
}
