param(
    [string]$DshRoot = 'D:\deepseek harness\deepseek-harness-master\deepseek-harness-master',
    [string]$Scenario = 'multi-turn'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$binary = Join-Path $DshRoot 'packages\examples\acp-demo\lib\bin.js'
$config = Join-Path $DshRoot 'examples\acp-agent\cordis.yml'
$fixture = Join-Path $DshRoot ("examples\acp-agent\tests\snapshots\$Scenario\session.jsonl")
foreach ($path in @($binary, $config, $fixture)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "DSH replay input is missing: $path"
    }
}

$probeHome = Join-Path ([System.IO.Path]::GetTempPath()) ("egopulse-dsh-replay-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $probeHome | Out-Null
$script:process = $null

function Read-JsonRpcLine([string]$label) {
    $task = $script:process.StandardOutput.ReadLineAsync()
    if (-not $task.Wait(15000)) {
        throw "DSH ACP replay timed out reading $label"
    }
    $line = $task.Result
    if ([string]::IsNullOrWhiteSpace($line)) {
        throw "DSH ACP replay returned an empty $label frame"
    }
    return $line
}

function Write-JsonRpc([object]$message) {
    $encoded = $message | ConvertTo-Json -Compress -Depth 10
    $script:process.StandardInput.WriteLine($encoded)
    $script:process.StandardInput.Flush()
    return $encoded
}

function New-Prompt([int]$id, [string]$sessionId, [string]$text) {
    return [pscustomobject]@{
        jsonrpc = '2.0'
        id = $id
        method = 'session/prompt'
        params = [pscustomobject]@{
            sessionId = $sessionId
            prompt = @([pscustomobject]@{ type = 'text'; text = $text })
        }
    }
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

    $frames = [System.Collections.Generic.List[string]]::new()
    $frames.Add((Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 1
        method = 'initialize'
        params = [pscustomobject]@{
            protocolVersion = 1
            clientCapabilities = [pscustomobject]@{}
            clientInfo = [pscustomobject]@{ name = 'egopulse-probe'; version = '0.1.0' }
        }
    })))
    $initialize = Read-JsonRpcLine 'initialize response'
    $initializeValue = $initialize | ConvertFrom-Json
    if ($null -eq $initializeValue.result -or $initializeValue.result.protocolVersion -ne 1) {
        throw "DSH ACP replay initialize failed: $initialize"
    }

    $frames.Add((Write-JsonRpc ([pscustomobject]@{
        jsonrpc = '2.0'
        id = 2
        method = 'session/new'
        params = [pscustomobject]@{ cwd = $DshRoot; mcpServers = @(); additionalDirectories = @() }
    })))
    $sessionResponse = Read-JsonRpcLine 'session/new response'
    $sessionValue = $sessionResponse | ConvertFrom-Json
    $sessionId = [string]$sessionValue.result.sessionId
    if ([string]::IsNullOrWhiteSpace($sessionId)) {
        throw "DSH ACP replay session/new did not return a session id: $sessionResponse"
    }

    $promptTexts = @('Reply with exactly the word: ONE. No tools.', 'Reply with exactly the word: TWO. No tools.')
    $promptResults = [System.Collections.Generic.List[object]]::new()
    $promptId = 3
    foreach ($text in $promptTexts) {
        $frames.Add((Write-JsonRpc (New-Prompt $promptId $sessionId $text)))
        $update = Read-JsonRpcLine "session/update for prompt $promptId"
        $result = Read-JsonRpcLine "session/prompt response $promptId"
        $updateValue = $update | ConvertFrom-Json
        $resultValue = $result | ConvertFrom-Json
        if ($updateValue.method -ne 'session/update' -or $updateValue.params.update.sessionUpdate -ne 'agent_message_chunk') {
            throw "DSH ACP replay returned an unexpected update: $update"
        }
        if ($resultValue.id -ne $promptId -or $resultValue.result.stopReason -ne 'end_turn') {
            throw "DSH ACP replay returned an unexpected prompt result: $result"
        }
        $promptResults.Add([pscustomobject]@{
            id = $promptId
            text = $updateValue.params.update.content.text
            stop_reason = $resultValue.result.stopReason
        })
        $promptId++
    }

    $script:process.StandardInput.Close()
    if (-not $script:process.WaitForExit(10000)) {
        $script:process.Kill()
        throw 'DSH ACP replay did not exit after stdin EOF'
    }
    $stderr = $script:process.StandardError.ReadToEnd().Trim()
    if ($script:process.ExitCode -ne 0 -or $stderr.Length -gt 0) {
        throw "DSH ACP replay process failed (exit=$($script:process.ExitCode)): $stderr"
    }

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $evidence = [string]::Join("`n", $frames)
        $digest = [BitConverter]::ToString(
            $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($evidence))
        ).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }

    [pscustomobject]@{
        candidate = 'deepseek-harness'
        scenario = $Scenario
        mode = 'replay'
        api_calls = $false
        prompt_sent_to_model = $false
        initialize = 'passed'
        session_new = 'passed'
        prompts = @($promptResults)
        stderr_empty = $true
        evidence_sha256 = $digest
    } | ConvertTo-Json -Compress -Depth 10
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
