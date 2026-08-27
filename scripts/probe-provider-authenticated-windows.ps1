param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("deepseek", "kimi", "glm")]
    [string]$Provider,

    [Parameter(Mandatory = $true)]
    [string]$ExactModel,

    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [switch]$AllowInference
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $AllowInference) {
    throw "This probe sends one real model prompt. Re-run with -AllowInference after confirming the local credential, exact model and isolated workspace policy."
}
if ($env:EGOPULSE_PROVIDER_AUTH_READY -ne "1") {
    throw "Set EGOPULSE_PROVIDER_AUTH_READY=1 only after the user-owned provider credential/profile is ready; secret values are never printed or passed as arguments."
}
if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
    throw "Provider executable does not exist: $ExecutablePath"
}
if ([string]::IsNullOrWhiteSpace($ExactModel)) {
    throw "ExactModel cannot be empty; fallback model selection is forbidden."
}

$env:EGOPULSE_ALLOW_PROVIDER_INFERENCE = "1"
$env:EGOPULSE_PROVIDER_AUTH_READY = "1"
$env:EGOPULSE_PROVIDER_EXACT_MODEL = $ExactModel
$env:EGOPULSE_PROVIDER_EXECUTABLE = $ExecutablePath

$repoRoot = Split-Path -Parent $PSScriptRoot
$package = switch ($Provider) {
    "deepseek" { "egopulse-dsh-adapter"; "authenticated_dsh_exact_model_terminal_lifecycle"; "EGOPULSE_DSH_NATIVE_EXE"; "EGOPULSE_DSH_EXACT_MODEL" }
    "kimi" { "egopulse-kimi-adapter"; "authenticated_kimi_exact_model_terminal_lifecycle"; "EGOPULSE_KIMI_NATIVE_EXE"; "EGOPULSE_KIMI_EXACT_MODEL" }
    "glm" { "egopulse-opencode-adapter"; "authenticated_glm_opencode_exact_model_terminal_lifecycle"; "EGOPULSE_OPENCODE_NATIVE_EXE"; "EGOPULSE_GLM_EXACT_MODEL" }
}

$envName = $package[2]
$modelEnvName = $package[3]
Set-Item -Path "Env:$envName" -Value $ExecutablePath
Set-Item -Path "Env:$modelEnvName" -Value $ExactModel

Write-Output "provider=$Provider"
Write-Output "exact_model=$ExactModel"
Write-Output "prompt_authorized=true"
Write-Output "secrets_printed=false"

Push-Location $repoRoot
try {
    & cargo test -p $package[0] --test authenticated_lifecycle $package[1] -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticated $Provider lifecycle probe failed; admission remains held."
    }
}
finally {
    Pop-Location
}
