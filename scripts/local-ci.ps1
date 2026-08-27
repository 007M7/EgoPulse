param(
    [string]$EvidenceDirectory = '.local-ci/evidence'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot
$env:CI = 'true'
$env:UV_CACHE_DIR = Join-Path $repoRoot '.cache/uv'

$steps = [System.Collections.Generic.List[object]]::new()
$startedAt = [DateTimeOffset]::UtcNow
$head = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve the current Git commit' }
$dirty = @(& git status --porcelain).Count -gt 0

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $Command $($Arguments -join ' ')"
    }
}

function Invoke-GateStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Output "local_ci_step=started name=$Name"
    try {
        & $Body
        $timer.Stop()
        $steps.Add([ordered]@{
            name = $Name
            status = 'passed'
            duration_ms = $timer.ElapsedMilliseconds
        })
        Write-Output "local_ci_step=passed name=$Name duration_ms=$($timer.ElapsedMilliseconds)"
    } catch {
        $timer.Stop()
        $steps.Add([ordered]@{
            name = $Name
            status = 'failed'
            duration_ms = $timer.ElapsedMilliseconds
            error = $_.Exception.Message
        })
        Write-Output "local_ci_step=failed name=$Name duration_ms=$($timer.ElapsedMilliseconds)"
        throw
    }
}

function Write-Evidence {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][string]$Failure
    )

    $finishedAt = [DateTimeOffset]::UtcNow
    $evidenceRoot = Join-Path $repoRoot $EvidenceDirectory
    New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null
    $report = [ordered]@{
        schema_version = 1
        status = $Status
        commit = $head
        worktree_dirty_at_start = $dirty
        started_at = $startedAt.ToString('o')
        finished_at = $finishedAt.ToString('o')
        duration_ms = [long]($finishedAt - $startedAt).TotalMilliseconds
        machine = $env:COMPUTERNAME
        steps = $steps
        failure = $Failure
    }
    $json = $report | ConvertTo-Json -Depth 8
    $stamp = $startedAt.ToString('yyyyMMddTHHmmssZ')
    $shortHead = $head.Substring(0, 12)
    Set-Content -LiteralPath (Join-Path $evidenceRoot "$stamp-$shortHead.json") -Value $json -Encoding utf8
    Set-Content -LiteralPath (Join-Path $evidenceRoot 'latest.json') -Value $json -Encoding utf8
}

try {
    Invoke-GateStep 'git-diff-integrity' {
        Invoke-External git diff --check
    }

    Invoke-GateStep 'locked-node-manifest' {
        # Local CI must not tear down/recreate node_modules on every run. The
        # frozen dry-run validates lockfile consistency; a clean checkout can
        # perform the explicit one-time `pnpm install --frozen-lockfile`.
        Invoke-External pnpm install --frozen-lockfile --lockfile-only --ignore-scripts --dry-run --reporter=append-only
    }

    Invoke-GateStep 'contracts-boundaries-typescript' {
        Invoke-External pnpm run check
    }

    Invoke-GateStep 'desktop-frontend' {
        Invoke-External pnpm --filter '@egopulse/desktop' run build
    }

    Invoke-GateStep 'rust-workspace' {
        & (Join-Path $PSScriptRoot 'check-rust.ps1')
        if ($LASTEXITCODE -ne 0) { throw "Rust gate failed with exit code $LASTEXITCODE" }
    }

    Invoke-GateStep 'python-foundation-probe' {
        Invoke-External uv sync --project workers/foundation-probe --frozen
        Invoke-External uv run --project workers/foundation-probe --frozen pytest workers/foundation-probe --rootdir workers/foundation-probe
    }

    Invoke-GateStep 'python-contract-bindings' {
        Invoke-External uv sync --project workers/contract-bindings --frozen
        Invoke-External uv run --project workers/contract-bindings --frozen pytest workers/contract-bindings --rootdir workers/contract-bindings
    }

    Invoke-GateStep 'python-memory-rag' {
        Invoke-External uv sync --project workers/memory-rag --frozen
        Invoke-External uv run --project workers/memory-rag --frozen pytest workers/memory-rag --rootdir workers/memory-rag
    }

    Write-Evidence -Status 'passed' -Failure $null
    Write-Output "local_ci=passed commit=$head dirty_at_start=$dirty"
} catch {
    Write-Evidence -Status 'failed' -Failure $_.Exception.Message
    Write-Error $_
    exit 1
}
