param()

$ErrorActionPreference = 'Stop'

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
$cargo = if ($cargoCommand) { $cargoCommand.Path } else { $null }
if (-not $cargo) {
    $rustupCargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $rustupCargo) {
        $cargo = $rustupCargo
    } else {
        throw 'Rust cargo is missing; install the rust-toolchain.toml toolchain before running this gate'
    }
}

$perl = Get-Command perl -ErrorAction SilentlyContinue
if (-not $perl) {
    $strawberryPerl = 'C:\Strawberry\perl\bin\perl.exe'
    if (Test-Path -LiteralPath $strawberryPerl) {
        $env:PATH = "$(Split-Path -Parent $strawberryPerl);$env:PATH"
        $perl = Get-Command perl -ErrorAction Stop
    } else {
        throw 'Perl is required to build vendored OpenSSL for SQLCipher; no Perl executable was found'
    }
}

$perlPath = if ($perl.Path) { $perl.Path } else { $perl.Source }
Write-Output "rust_prerequisite=perl path=$perlPath"

& $cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cargo clippy --workspace --all-targets --locked -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cargo build -p egopulse-cli --bin egopulse --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Real-process E2E tests launch both user surfaces from target/debug. Rebuild
# both against the same negotiated contract digest before starting agentosd.
& $cargo build -p egopulse-tui --bin egopulse-tui --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cargo build -p egopulse-agentosd --bin agentosd --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& (Join-Path $PSScriptRoot 'test-install-egopulse.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cargo test --workspace --exclude egopulse-agentosd --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Daemon integration targets cover Verification intake, Artifact returns,
# Verdict settlement and recovery in addition to the CLI/TUI C5 fixture.
# Select every target so a new integration test cannot silently miss the gate.
# These tests own child daemons and Named Pipes, so keep each binary serial.
# Explicitly ignored live-provider tests remain a separate acceptance step.
& $cargo test -p egopulse-agentosd --lib --bins --tests --locked -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
