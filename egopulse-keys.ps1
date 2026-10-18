# DPAPI CurrentUser, with the platform key-file reader's pinned entropy.
function Import-EgoPulseProtectedKeys {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string[]]$Names)
    Add-Type -AssemblyName System.Security
    $entropy = [Text.Encoding]::UTF8.GetBytes("egopulse/local-ipc/client-record/v1`0")
    $plain = $null
    try {
        $protected = [IO.File]::ReadAllBytes($Path)
        if ($protected.Length -eq 0 -or $protected.Length -gt 65536) { throw 'LOCAL_KEYS_INVALID' }
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($protected, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $payload = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
        if ($payload.schema_version -cne 'egopulse.local-keys/v1' -or @($payload.keys.PSObject.Properties).Count -ne $Names.Count) { throw 'LOCAL_KEYS_INVALID' }
        foreach ($name in $Names) {
            $property = $payload.keys.PSObject.Properties[$name]
            if ($null -eq $property -or [string]$property.Value -cnotmatch '\A[0-9a-fA-F]{64}\z') { throw 'LOCAL_KEYS_INVALID' }
        }
        foreach ($name in $Names) { [Environment]::SetEnvironmentVariable($name, [string]$payload.keys.PSObject.Properties[$name].Value, 'Process') }
    } catch { throw 'Protected installation keys could not be loaded (LOCAL_KEYS_INVALID). Restore the matching DPAPI backup on the same Windows account.' }
    finally { if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) } }
}

function New-EgoPulseProtectedKeys {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string[]]$Names)
    Add-Type -AssemblyName System.Security
    $keys = [ordered]@{}
    foreach ($name in $Names) { $keys[$name] = New-RandomHex }
    $payload = [ordered]@{ schema_version = 'egopulse.local-keys/v1'; keys = $keys }
    $plain = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 4 -Compress))
    $entropy = [Text.Encoding]::UTF8.GetBytes("egopulse/local-ipc/client-record/v1`0")
    try {
        $protected = [Security.Cryptography.ProtectedData]::Protect($plain, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($protected, 0, $protected.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    } finally { [Array]::Clear($plain, 0, $plain.Length) }
    Import-EgoPulseProtectedKeys -Path $Path -Names $Names
}
