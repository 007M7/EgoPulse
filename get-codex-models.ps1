#Requires -Version 7.0
param(
    [string]$CodexExecutable,
    [ValidateRange(5,120)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-BoundedMetadataLine {
    param([IO.StreamReader]$Reader, [DateTimeOffset]$Deadline)
    $line = [Text.StringBuilder]::new()
    $character = [char[]]::new(1)
    while ([DateTimeOffset]::UtcNow -lt $Deadline) {
        $remaining = [Math]::Max(1, [int]($Deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        $read = $Reader.ReadAsync($character, 0, 1)
        if (-not $read.Wait($remaining) -or $read.Result -eq 0) { throw 'Incomplete metadata frame.' }
        if ($character[0] -eq "`n") { return $line.ToString() }
        if ($line.Length -ge 1048576) { throw 'Metadata frame exceeds the supported limit.' }
        $null = $line.Append($character[0])
    }
    throw 'Metadata frame timed out.'
}

$process = $null
$started = $false
try {
# Query the installed Harness using its own login. No thread or turn is
# created, and no authentication contents or native diagnostics are returned.
if ([string]::IsNullOrWhiteSpace($CodexExecutable)) {
    $command = Get-Command codex -ErrorAction Stop
    $CodexExecutable = $command.Source
    if ([IO.Path]::GetExtension($CodexExecutable) -ne '.exe') {
        $commandRoot = Split-Path -Parent $CodexExecutable
        $candidates = @(@(
            'node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe',
            'node_modules/@openai/codex/vendor/x86_64-pc-windows-msvc/bin/codex.exe'
        ) | ForEach-Object { Join-Path $commandRoot $_ } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
        if (-not $candidates.Count) { throw 'Pass -CodexExecutable with the installed codex.exe path.' }
        $CodexExecutable = $candidates[0]
    }
}
$executable = (Resolve-Path -LiteralPath $CodexExecutable).Path
if ([IO.Path]::GetExtension($executable) -ne '.exe') { throw 'CodexExecutable must name a native codex.exe, not a shell command.' }
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $executable
$start.ArgumentList.Add('app-server')
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [Diagnostics.Process]::new()
$process.StartInfo = $start
$complete = $false
$models = [Collections.Generic.List[object]]::new()
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenCursors = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $started = $process.Start()
    # Drain diagnostics without printing or persisting potentially private data.
    $errorDrain = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $requestId = 1
    $process.StandardInput.WriteLine('{"id":1,"method":"initialize","params":{"clientInfo":{"name":"egopulse_model_catalog","title":"EgoPulse Model Catalog","version":"0.1.0"},"capabilities":{}}}')
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $frame = Read-BoundedMetadataLine -Reader $process.StandardOutput -Deadline $deadline
        $message = ConvertFrom-Json -InputObject $frame
        if ($message -isnot [pscustomobject]) { throw 'Invalid metadata object.' }
        if (-not $message.PSObject.Properties['id'] -or $message.id -ne $requestId) { continue }
        if ($message.PSObject.Properties['error']) { throw 'Codex rejected model discovery; check the Harness login and version.' }
        if (-not $message.PSObject.Properties['result'] -or $message.result -isnot [pscustomobject]) {
            throw 'Invalid metadata result.'
        }
        if ($requestId -eq 1) {
            $process.StandardInput.WriteLine('{"method":"initialized","params":{}}')
            $requestId = 2
            $process.StandardInput.WriteLine('{"id":2,"method":"model/list","params":{"limit":100,"includeHidden":false}}')
            continue
        }
        if (-not $message.result.PSObject.Properties['data'] -or $message.result.data -isnot [array] -or
            -not $message.result.PSObject.Properties['nextCursor']) { throw 'Invalid model catalog.' }
        foreach ($entry in $message.result.data) {
            if ($entry -isnot [pscustomobject] -or -not $entry.PSObject.Properties['model'] -or
                $entry.model -isnot [string] -or -not $entry.PSObject.Properties['isDefault'] -or
                $entry.isDefault -isnot [bool]) { throw 'Invalid model catalog entry.' }
            $model = [string]$entry.model
            if ($model -notmatch '\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\z' -or -not $seen.Add($model)) {
                throw 'Codex returned an invalid or duplicate model identity.'
            }
            $models.Add([ordered]@{ model = $model; is_default = [bool]$entry.isDefault })
        }
        if ($models.Count -gt 256) { throw 'Codex model catalog exceeds the supported limit.' }
        $cursor = $message.result.nextCursor
        if ($null -eq $cursor) { $complete = $true; break }
        if ($cursor -isnot [string] -or $cursor.Length -eq 0 -or $cursor.Length -gt 4096 -or
            $cursor -match '[\x00-\x1f\x7f]' -or -not $seenCursors.Add($cursor)) { throw 'Invalid pagination cursor.' }
        $requestId++
        if ($requestId -gt 10) { throw 'Codex model pagination exceeds the supported limit.' }
        $process.StandardInput.WriteLine((@{ id=$requestId; method='model/list'; params=@{limit=100; includeHidden=$false; cursor=$message.result.nextCursor} } | ConvertTo-Json -Depth 5 -Compress))
    }
    if (-not $complete -or -not $models.Count) { throw 'Codex returned no complete model catalog.' }
    [ordered]@{
        schema_version = 'egopulse.codex-model-catalog/v1'
        source = 'codex-app-server:model/list'
        executable = $executable
        fetched_at = [DateTimeOffset]::UtcNow.ToString('o')
        models = @($models.ToArray())
        inference_started = $false
    } | ConvertTo-Json -Depth 6
} catch {
    throw 'EGOPULSE_CODEX_MODEL_DISCOVERY_FAILED: Check the installed codex.exe, Harness login, and supported App Server model/list protocol. Native diagnostics are suppressed.'
} finally {
    if ($null -ne $process) {
        try {
            if ($started -and -not $process.HasExited) { $process.Kill($true); $null = $process.WaitForExit(5000) }
        } catch { }
        $process.Dispose()
    }
}

