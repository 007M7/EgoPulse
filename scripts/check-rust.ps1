param()

$ErrorActionPreference = 'Stop'

$cargo = (Get-Command cargo -ErrorAction SilentlyContinue).Source
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

Write-Output "rust_prerequisite=perl path=$($perl.Source)"

& $cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cargo clippy --workspace --all-targets --locked -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cargo test --workspace --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
