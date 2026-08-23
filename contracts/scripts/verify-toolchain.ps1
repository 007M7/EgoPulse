$ErrorActionPreference = 'Stop'

$candidateRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolchainRoot = Join-Path $candidateRoot 'toolchain'
$generatedRoot = Join-Path $toolchainRoot 'generated'
$evidenceRoot = Join-Path $toolchainRoot 'evidence'
$cargoToolRoot = Join-Path $toolchainRoot '.tools\cargo'
$taskBufCache = Join-Path $toolchainRoot '.tools\buf-cache'
$taskUvCache = Join-Path $toolchainRoot '.tools\uv-cache'
$taskCargoCache = Join-Path $toolchainRoot '.tools\cargo-cache'
$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -ne $cargoCommand) {
    $cargoExe = $cargoCommand.Source
} else {
    $cargoExe = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
}
if (-not (Test-Path -LiteralPath $cargoExe)) {
    throw "cargo executable not found: $cargoExe"
}

if (Test-Path -LiteralPath $generatedRoot) {
    Remove-Item -LiteralPath $generatedRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $generatedRoot, $evidenceRoot, $taskBufCache, $taskUvCache, $taskCargoCache | Out-Null

$env:BUF_CACHE_DIR = $taskBufCache
$env:UV_CACHE_DIR = $taskUvCache
$env:CARGO_HOME = $taskCargoCache
$env:PATH = "$(Join-Path $toolchainRoot 'node_modules\.bin');$(Join-Path $cargoToolRoot 'bin');$env:PATH"

Push-Location $candidateRoot
try {
    & buf --version
    if ($LASTEXITCODE -ne 0) { throw 'buf version failed' }
    & buf lint
    if ($LASTEXITCODE -ne 0) { throw 'buf lint failed' }
    & buf build --exclude-source-info -o (Join-Path $evidenceRoot 'buf-image.binpb')
    if ($LASTEXITCODE -ne 0) { throw 'buf build failed' }

    $protoFiles = Get-ChildItem -LiteralPath (Join-Path $candidateRoot 'proto') -Recurse -Filter '*.proto' -File |
        Sort-Object FullName |
        ForEach-Object { $_.FullName.Substring((Join-Path $candidateRoot 'proto').Length + 1).Replace('\', '/') }
    $pythonOut = Join-Path $generatedRoot 'python'
    New-Item -ItemType Directory -Force -Path $pythonOut | Out-Null
    & uv run --project (Join-Path $toolchainRoot 'python') --frozen python -m grpc_tools.protoc --version
    if ($LASTEXITCODE -ne 0) { throw 'protoc version failed' }
    $protocArgs = @(
        '-m', 'grpc_tools.protoc',
        '-I', (Join-Path $candidateRoot 'proto'),
        "--descriptor_set_out=$(Join-Path $evidenceRoot 'protoc-image.binpb')",
        '--include_imports',
        "--python_out=$pythonOut",
        "--pyi_out=$pythonOut"
    ) + $protoFiles
    & uv run --project (Join-Path $toolchainRoot 'python') --frozen python @protocArgs
    if ($LASTEXITCODE -ne 0) { throw 'protoc compile/Python generation failed' }

    & buf generate --template (Join-Path $candidateRoot 'buf.gen.yaml')
    if ($LASTEXITCODE -ne 0) { throw 'buf cross-language generation failed' }
    & pnpm --dir $toolchainRoot run typecheck
    if ($LASTEXITCODE -ne 0) { throw 'TypeScript generated code typecheck failed' }
    & $cargoExe test --manifest-path (Join-Path $toolchainRoot 'rust-generated-check\Cargo.toml') --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust generated code compilation failed' }
    & uv run --project (Join-Path $toolchainRoot 'python') --frozen python (Join-Path $toolchainRoot 'python\verify_generated.py')
    if ($LASTEXITCODE -ne 0) { throw 'Python generated code import failed' }

    $bufHash = (Get-FileHash -LiteralPath (Join-Path $evidenceRoot 'buf-image.binpb') -Algorithm SHA256).Hash.ToLowerInvariant()
    $protocHash = (Get-FileHash -LiteralPath (Join-Path $evidenceRoot 'protoc-image.binpb') -Algorithm SHA256).Hash.ToLowerInvariant()
    $tsCount = (Get-ChildItem -LiteralPath (Join-Path $generatedRoot 'typescript') -Recurse -Filter '*.ts' -File).Count
    $rustCount = (Get-ChildItem -LiteralPath (Join-Path $generatedRoot 'rust') -Recurse -Filter '*.rs' -File).Count
    $pythonCount = (Get-ChildItem -LiteralPath $pythonOut -Recurse -Filter '*_pb2.py' -File).Count
    Write-Output "buf_image_sha256=$bufHash"
    Write-Output "protoc_image_sha256=$protocHash"
    Write-Output "generated_typescript_files=$tsCount"
    Write-Output "generated_rust_files=$rustCount"
    Write-Output "generated_python_modules=$pythonCount"
}
finally {
    Pop-Location
}
