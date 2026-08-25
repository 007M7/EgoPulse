param(
    [string]$DshRoot = 'D:\deepseek harness\deepseek-harness-master\deepseek-harness-master'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$binary = Join-Path $DshRoot 'packages\examples\acp-demo\lib\bin.js'
$config = Join-Path $DshRoot 'examples\acp-agent\cordis.yml'
$fixture = Join-Path $DshRoot 'examples\acp-agent\tests\snapshots\handshake\session.jsonl'
foreach ($path in @($binary, $config, $fixture)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "DSH ACP recovery capability input is missing: $path"
    }
}

$probeHome = Join-Path ([System.IO.Path]::GetTempPath()) ("egopulse-dsh-recovery-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $probeHome | Out-Null
$script:process = $null

function Read-JsonRpcLine([string]$label) {
    $task = $script:process.StandardOutput.ReadLineAsync()
    if (-not $task.Wait(15000)) {
        throw "DSH ACP recovery probe timed out reading $label"
    }
    $line = $task.Result
    if ([string]::IsNullOrWhiteSpace($line)) {
        throw "DSH ACP recovery probe returned an empty $label frame"
    }
    return $line
}

function Write-JsonRpc([object]$message) {
    $script:process.StandardInput.WriteLine(($message | ConvertTo-Json -Compress -Depth 10))
    $script:process.StandardInput.Flush()
}

try {
    $oldSnapshot = $env:DSH_SNAPSHOT
    $oldSnapshotFile = $env:DSH_SNAPSHOT_FILE
    $oldSessionsRoot = $env:DSH_SNAPSHOT_SESSIONS_ROOT
    $oldHome = $env:DSH_HOME
    $env:DSH_SNAPSHOT = 'replay'
    $env:DSH_SNAPSHOT_FILE = $fixture
    $env:DSH_SNAPSHOT_SESSIONS_ROOT = Join-Path $probeHome 'sessions'
    $env:DSH_HOME = Join-Path $probeHome '.dsh'

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command node -ErrorAction Stop).Source
    $startInfo.WorkingDirectory = $DshRoot
    $startInfo.Arguments = 'packages/examples/acp-demo/lib/bin.js --config examples/acp-agent/cordis.yml'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $script:process = [System.Diagnostics.Process]::new()
    $script:process.StartInfo = $startInfo
    [void]$script:process.Start()

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 1
        method = 'initialize'
        params = [pscustomobject]@{
            protocolVersion = 1
            clientCapabilities = [pscustomobject]@{}
            clientInfo = [pscustomobject]@{ name = 'egopulse-recovery-probe'; version = '0.1.0' }
        }
    })
    $initialize = Read-JsonRpcLine 'initialize response'
    $initializeValue = $initialize | ConvertFrom-Json
    if ($null -eq $initializeValue.result -or $initializeValue.result.protocolVersion -ne 1) {
        throw "DSH ACP recovery initialize failed: $initialize"
    }

    $agentCapabilities = $initializeValue.result.agentCapabilities
    $loadAdvertised = $false
    if ($null -ne $agentCapabilities -and $agentCapabilities.PSObject.Properties.Name -contains 'loadSession') {
        $loadAdvertised = [bool]$agentCapabilities.loadSession
    }

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 2
        method = 'session/new'
        params = [pscustomobject]@{ cwd = $probeHome; mcpServers = @(); additionalDirectories = @() }
    })
    $sessionNew = Read-JsonRpcLine 'session/new response'
    $sessionNewValue = $sessionNew | ConvertFrom-Json
    if ($null -eq $sessionNewValue.result -or [string]::IsNullOrWhiteSpace([string]$sessionNewValue.result.sessionId)) {
        throw "DSH ACP recovery session/new failed: $sessionNew"
    }

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 3
        method = 'session/load'
        params = [pscustomobject]@{ sessionId = 'egopulse-missing-session' }
    })
    $loadResponse = Read-JsonRpcLine 'session/load response'
    $loadValue = $loadResponse | ConvertFrom-Json
    $loadRejected = $null -ne $loadValue.error

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 4
        method = 'session/resume'
        params = [pscustomobject]@{ sessionId = 'egopulse-missing-session'; cwd = $probeHome }
    })
    $resumeResponse = Read-JsonRpcLine 'session/resume response'
    $resumeValue = $resumeResponse | ConvertFrom-Json
    $resumeRejected = $null -ne $resumeValue.error

    # The DSH ACP demo keeps its stdio loop alive after an unsupported-method
    # response. The capability assertion is already complete, so terminate the
    # isolated no-side-effect probe explicitly rather than treating that loop
    # lifetime as recovery evidence.
    if (-not $script:process.HasExited) {
        $script:process.Kill()
        if (-not $script:process.WaitForExit(5000)) {
            throw 'DSH ACP recovery capability probe could not be terminated'
        }
    }
    $stderr = $script:process.StandardError.ReadToEnd().Trim()
    if ($stderr -notmatch '"Method not found": session/load' -or $stderr -notmatch '"Method not found": session/resume') {
        throw "DSH ACP recovery capability probe returned unexpected stderr: $stderr"
    }
    if ($loadAdvertised -or -not $loadRejected -or -not $resumeRejected) {
        throw "unexpected recovery capability result: loadAdvertised=$loadAdvertised loadRejected=$loadRejected resumeRejected=$resumeRejected"
    }

    [pscustomobject]@{
        candidate = 'deepseek-harness'
        protocol = 'agent-client-protocol'
        mode = 'replay'
        api_calls = $false
        initialize = 'passed'
        load_session_advertised = $false
        session_load = 'rejected_not_supported'
        session_resume = 'rejected_not_supported'
        restart_reconciliation = 'held_native_recovery_unsupported'
        process_termination = 'forced_after_no_side_effect_probe'
        stderr_empty = $false
        stderr_contains_expected_unsupported_method_errors = $true
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $script:process -and -not $script:process.HasExited) {
        $script:process.Kill()
    }
    if ($null -eq $oldSnapshot) { Remove-Item Env:DSH_SNAPSHOT -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT = $oldSnapshot }
    if ($null -eq $oldSnapshotFile) { Remove-Item Env:DSH_SNAPSHOT_FILE -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT_FILE = $oldSnapshotFile }
    if ($null -eq $oldSessionsRoot) { Remove-Item Env:DSH_SNAPSHOT_SESSIONS_ROOT -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT_SESSIONS_ROOT = $oldSessionsRoot }
    if ($null -eq $oldHome) { Remove-Item Env:DSH_HOME -ErrorAction SilentlyContinue } else { $env:DSH_HOME = $oldHome }
    Remove-Item -LiteralPath $probeHome -Recurse -Force -ErrorAction SilentlyContinue
}
