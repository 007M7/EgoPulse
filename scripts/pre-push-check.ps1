param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot

& git diff --check
if ($LASTEXITCODE -ne 0) { throw 'Git diff check failed' }

& pnpm run check
if ($LASTEXITCODE -ne 0) { throw 'Fast pre-push contract and TypeScript checks failed' }

Write-Output 'pre_push_check=passed scope=diff-contracts-typescript'
