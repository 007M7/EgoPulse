param(
    [string]$Command = 'dsh'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolved = Get-Command $Command -ErrorAction Stop
$probeHome = Join-Path ([System.IO.Path]::GetTempPath()) ("egopulse-dsh-probe-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $probeHome | Out-Null

function Invoke-Dsh([string[]]$Arguments) {
    $output = @(& $resolved.Source @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "DSH probe command failed (exit=$exitCode): $($Arguments -join ' ')`n$($output -join "`n")"
    }
    return $output
}

try {
    $oldHome = $env:DSH_HOME
    $oldMode = $env:DSH_PERMISSION_MODE
    $env:DSH_HOME = $probeHome
    $env:DSH_PERMISSION_MODE = 'read-only'

    $version = (Invoke-Dsh @('--version') | Select-Object -First 1).ToString().Trim()
    $config = Invoke-Dsh @('--profile', 'cli', '--dump-config')
    $help = Invoke-Dsh @('--profile', 'cli', '--help')

    if (-not ($config -match "dsh-cli-app")) {
        throw 'DSH CLI profile dump did not contain the CLI app layer'
    }
    if (-not ($help -match 'Start an interactive agent session')) {
        throw 'DSH CLI profile help did not reach the profile application'
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $evidence = [string]::Join("`n", @($version) + $config + $help)
        $digest = [BitConverter]::ToString(
            $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($evidence))
        ).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }

    [pscustomobject]@{
        candidate = 'deepseek-harness'
        version = $version
        home_isolated = $true
        permission_mode = $env:DSH_PERMISSION_MODE
        api_calls = $false
        prompt_sent = $false
        cli_profile_bootstrap = 'passed'
        evidence_sha256 = $digest
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -eq $oldHome) {
        Remove-Item Env:DSH_HOME -ErrorAction SilentlyContinue
    }
    else {
        $env:DSH_HOME = $oldHome
    }
    if ($null -eq $oldMode) {
        Remove-Item Env:DSH_PERMISSION_MODE -ErrorAction SilentlyContinue
    }
    else {
        $env:DSH_PERMISSION_MODE = $oldMode
    }
    Remove-Item -LiteralPath $probeHome -Recurse -Force -ErrorAction SilentlyContinue
}
