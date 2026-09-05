param(
    [string]$Remote = 'origin',
    [string]$Branch = '',
    [string]$Proxy = '',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot

if ([string]::IsNullOrWhiteSpace($Branch)) {
    $Branch = (& git symbolic-ref --short HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Branch)) {
        throw 'A branch is required when HEAD is detached'
    }
}

# Keep the authoritative check, but invoke it directly. The repository POSIX
# pre-push hook cannot start reliably in the restricted Windows shell used by
# some task runners (MSYS signal-pipe error 5).
& (Join-Path $PSScriptRoot 'pre-push-check.ps1')
if ($LASTEXITCODE -ne 0) { throw "Pre-push check failed with exit code $LASTEXITCODE" }

$token = (& gh auth token).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
    throw 'GitHub CLI authentication is unavailable; run gh auth login first'
}

if ([string]::IsNullOrWhiteSpace($Proxy)) {
    $Proxy = [Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Process')
}

$basic = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes(('x-access-token:' + $token))
)
$env:GIT_TERMINAL_PROMPT = '0'

$gitArgs = @(
    '-c', 'core.hooksPath=NUL',
    '-c', 'http.sslBackend=openssl',
    '-c', 'credential.helper=',
    '-c', "http.extraHeader=Authorization: Basic $basic"
)
if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
    $gitArgs += @('-c', "http.proxy=$Proxy", '-c', "https.proxy=$Proxy")
}

$gitArgs += @('push')
if ($DryRun) { $gitArgs += '--dry-run' }
$gitArgs += @($Remote, "HEAD:$Branch")

& git @gitArgs
if ($LASTEXITCODE -ne 0) { throw "GitHub push failed with exit code $LASTEXITCODE" }

if ($DryRun) {
    Write-Output "github_push=dry-run remote=$Remote branch=$Branch"
} else {
    Write-Output "github_push=passed remote=$Remote branch=$Branch"
}
