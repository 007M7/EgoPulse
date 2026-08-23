param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot

& git config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) { throw 'Unable to configure the repository Git hooks path' }

$configured = (& git config --get core.hooksPath).Trim()
if ($configured -ne '.githooks') {
    throw "Unexpected Git hooks path after installation: $configured"
}

Write-Output 'git_hooks=installed path=.githooks pre_push=local_ci'
