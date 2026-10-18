$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../egopulse-keys.ps1')
function New-RandomHex {
    $bytes=New-Object byte[] 32
    $generator=[Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
$names=@('EGOPULSE_TASK_KEY_HEX','EGOPULSE_MEMORY_KEY_HEX','EGOPULSE_ARTIFACT_KEY_HEX','EGOPULSE_VERIFICATION_KEY_HEX','EGOPULSE_POLICY_KEY_HEX','EGOPULSE_VERDICT_KEY_HEX','EGOPULSE_ADAPTER_KEY_HEX','EGOPULSE_COLLABORATION_KEY_HEX','EGOPULSE_READ_MODEL_KEY_HEX','EGOPULSE_TOKEN_MAC_KEY_HEX')
$root=Join-Path ([IO.Path]::GetTempPath()) "egopulse-dpapi-test-$([Guid]::NewGuid().ToString('N'))"
$null=New-Item -ItemType Directory -Path $root
$path=Join-Path $root 'keys.dpapi'
$processBefore=@{}; $userBefore=@{}
foreach ($name in $names) { $processBefore[$name]=[Environment]::GetEnvironmentVariable($name,'Process'); $userBefore[$name]=[Environment]::GetEnvironmentVariable($name,'User') }
try {
    New-EgoPulseProtectedKeys -Path $path -Names $names
    $initial=@{}; foreach ($name in $names) { $initial[$name]=[Environment]::GetEnvironmentVariable($name,'Process'); [Environment]::SetEnvironmentVariable($name,$null,'Process') }
    Import-EgoPulseProtectedKeys -Path $path -Names $names
    $binary=[IO.File]::ReadAllBytes($path)
    foreach ($name in $names) {
        if ([Environment]::GetEnvironmentVariable($name,'Process') -cne $initial[$name]) { throw 'DPAPI reload changed a key' }
        if ([Environment]::GetEnvironmentVariable($name,'User') -cne $userBefore[$name]) { throw 'DPAPI wrote a User secret' }
        if ([Text.Encoding]::UTF8.GetString($binary).Contains($initial[$name])) { throw 'plaintext key persisted' }
    }
    $rejected=$false
    try { New-EgoPulseProtectedKeys -Path $path -Names $names } catch { $rejected=$true }
    if (-not $rejected) { throw 'existing key file was overwritten' }
    $binary[$binary.Length-1]=$binary[$binary.Length-1] -bxor 1
    [IO.File]::WriteAllBytes($path,$binary)
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,'unchanged','Process') }
    $rejected=$false
    try { Import-EgoPulseProtectedKeys -Path $path -Names $names } catch { $rejected=$true }
    if (-not $rejected) { throw 'tampered key file accepted' }
    foreach ($name in $names) { if ([Environment]::GetEnvironmentVariable($name,'Process') -cne 'unchanged') { throw 'failed import partially injected keys' } }
    Write-Output 'protected_keys_test=passed round_trip=true user_secrets_unchanged=true tamper_refused=true no_clobber=true'
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$processBefore[$name],'Process') }
    $resolved=[IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) { throw 'test cleanup escaped temp root' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
