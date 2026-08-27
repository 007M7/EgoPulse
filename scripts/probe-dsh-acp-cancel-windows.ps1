param(
    [string]$DshRoot = 'D:\deepseek harness\deepseek-harness-master\deepseek-harness-master'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$binary = Join-Path $DshRoot 'packages\examples\acp-demo\lib\bin.js'
$config = Join-Path $DshRoot 'examples\acp-agent\cordis.yml'
$fixture = Join-Path $DshRoot 'examples\acp-agent\tests\snapshots\cancel\session.jsonl'
$override = Join-Path $DshRoot 'examples\acp-agent\tests\snapshots\cancel\replay.override.json'
foreach ($path in @($binary, $config, $fixture, $override)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "DSH cancel replay input is missing: $path"
    }
}

$probeHome = Join-Path ([System.IO.Path]::GetTempPath()) ("egopulse-dsh-cancel-" + [Guid]::NewGuid().ToString('N'))
$workspace = Join-Path $probeHome 'workspace'
New-Item -ItemType Directory -Force -Path $workspace | Out-Null
$script:process = $null

function Read-JsonRpcLine([string]$label) {
    $task = $script:process.StandardOutput.ReadLineAsync()
    if (-not $task.Wait(15000)) { throw "DSH cancel replay timed out reading $label" }
    if ([string]::IsNullOrWhiteSpace($task.Result)) { throw "empty $label frame" }
    return $task.Result
}

function Write-JsonRpc([object]$message) {
    $script:process.StandardInput.WriteLine(($message | ConvertTo-Json -Compress -Depth 10))
    $script:process.StandardInput.Flush()
}

try {
    $oldSnapshot = $env:DSH_SNAPSHOT
    $oldSnapshotFile = $env:DSH_SNAPSHOT_FILE
    $oldSnapshotOverride = $env:DSH_SNAPSHOT_OVERRIDE
    $oldSessionsRoot = $env:DSH_SNAPSHOT_SESSIONS_ROOT
    $oldHome = $env:DSH_HOME
    $env:DSH_SNAPSHOT = 'replay'
    $env:DSH_SNAPSHOT_FILE = $fixture
    $env:DSH_SNAPSHOT_OVERRIDE = $override
    $env:DSH_SNAPSHOT_SESSIONS_ROOT = Join-Path $probeHome 'sessions'
    $env:DSH_HOME = Join-Path $probeHome '.dsh'

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command node -ErrorAction Stop).Source
    $startInfo.WorkingDirectory = $workspace
    $startInfo.Arguments = ('"{0}" --config "{1}"' -f $binary, $config)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $script:process = [System.Diagnostics.Process]::new()
    $script:process.StartInfo = $startInfo
    [void]$script:process.Start()

    $script:process.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"egopulse-probe","version":"0.1.0"}}}')
    $initialize = Read-JsonRpcLine 'initialize response'
    $initializeValue = $initialize | ConvertFrom-Json
    if ($initializeValue.result.protocolVersion -ne 1) { throw "initialize failed: $initialize" }

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 2
        method = 'session/new'
        params = [pscustomobject]@{ cwd = $workspace; mcpServers = @(); additionalDirectories = @() }
    })
    $sessionNew = Read-JsonRpcLine 'session/new response'
    $sessionId = [string](($sessionNew | ConvertFrom-Json).result.sessionId)
    if ([string]::IsNullOrWhiteSpace($sessionId)) { throw "session/new failed: $sessionNew" }

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 3
        method = 'session/prompt'
        params = [pscustomobject]@{
            sessionId = $sessionId
            prompt = @([pscustomobject]@{ type = 'text'; text = 'Start a long task; this turn will be cancelled mid-stream.' })
        }
    })
    $ready = Join-Path $workspace '.dsh-snapshot-stream-ready'
    $deadline = (Get-Date).AddSeconds(15)
    while (-not (Test-Path -LiteralPath $ready) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $ready)) { throw 'cancel replay did not reach ready marker' }

    Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        method = 'session/cancel'
        params = [pscustomobject]@{ sessionId = $sessionId }
    })
    $cancelResult = Read-JsonRpcLine 'cancelled prompt response'
    $cancelValue = $cancelResult | ConvertFrom-Json
    if ($cancelValue.id -ne 3 -or $cancelValue.result.stopReason -ne 'cancelled') {
        throw "unexpected cancel result: $cancelResult"
    }

    $script:process.StandardInput.Close()
    if (-not $script:process.WaitForExit(10000)) { $script:process.Kill(); throw 'cancel replay did not exit' }
    $stderr = $script:process.StandardError.ReadToEnd().Trim()
    if ($script:process.ExitCode -ne 0 -or $stderr.Length -gt 0) {
        throw "cancel replay process failed (exit=$($script:process.ExitCode)): $stderr"
    }

    [pscustomobject]@{
        candidate = 'deepseek-harness'
        scenario = 'cancel'
        mode = 'replay'
        api_calls = $false
        initialize = 'passed'
        session_new = 'passed'
        native_cancel = 'passed'
        stop_reason = 'cancelled'
        stderr_empty = $true
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $script:process -and -not $script:process.HasExited) { $script:process.Kill() }
    if ($null -eq $oldSnapshot) { Remove-Item Env:DSH_SNAPSHOT -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT = $oldSnapshot }
    if ($null -eq $oldSnapshotFile) { Remove-Item Env:DSH_SNAPSHOT_FILE -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT_FILE = $oldSnapshotFile }
    if ($null -eq $oldSnapshotOverride) { Remove-Item Env:DSH_SNAPSHOT_OVERRIDE -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT_OVERRIDE = $oldSnapshotOverride }
    if ($null -eq $oldSessionsRoot) { Remove-Item Env:DSH_SNAPSHOT_SESSIONS_ROOT -ErrorAction SilentlyContinue } else { $env:DSH_SNAPSHOT_SESSIONS_ROOT = $oldSessionsRoot }
    if ($null -eq $oldHome) { Remove-Item Env:DSH_HOME -ErrorAction SilentlyContinue } else { $env:DSH_HOME = $oldHome }
    Remove-Item -LiteralPath $probeHome -Recurse -Force -ErrorAction SilentlyContinue
}
