$ErrorActionPreference = 'Stop'

$candidateRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $candidateRoot 'toolchain\fault-conformance\Cargo.toml'
$repositoryRoot = (& git -C $candidateRoot rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repositoryRoot)) {
    throw 'unable to resolve repository root for short Cargo paths'
}
$workspaceRoot = Split-Path -Parent $repositoryRoot
$cargoCache = Join-Path $workspaceRoot '.cache\cargo-g3fault'
$cargoTarget = Join-Path $workspaceRoot '.cache\g3fault-target'

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -ne $cargoCommand) {
    $cargoExe = $cargoCommand.Source
} else {
    $cargoExe = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
}
if (-not (Test-Path -LiteralPath $cargoExe)) {
    throw "cargo executable not found: $cargoExe"
}

$perlCommand = Get-Command perl -ErrorAction SilentlyContinue
if ($null -eq $perlCommand) {
    $strawberryPerl = 'C:\Strawberry\perl\bin'
    $strawberryCompiler = 'C:\Strawberry\c\bin'
    if (-not (Test-Path -LiteralPath (Join-Path $strawberryPerl 'perl.exe'))) {
        throw 'Perl is required to build vendored OpenSSL for SQLCipher'
    }
    $env:PATH = "$strawberryPerl;$strawberryCompiler;$env:PATH"
}

New-Item -ItemType Directory -Force -Path $cargoCache, $cargoTarget | Out-Null
$env:CARGO_HOME = $cargoCache
$env:CARGO_TARGET_DIR = $cargoTarget

& $cargoExe test --manifest-path $manifestPath --locked -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'Gate 3 SQLCipher crash-recovery conformance failed'
}
