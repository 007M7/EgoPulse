param(
    [ValidateSet('Write', 'Check')]
    [string]$Mode = 'Check'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$contractsRoot = Join-Path $repositoryRoot 'contracts'
$contractManifestPath = Join-Path $contractsRoot 'manifest.json'
$cacheRoot = Join-Path $repositoryRoot '.cache\contract-codegen'
$stagingRoot = Join-Path $cacheRoot 'staging'
$typescriptStage = Join-Path $stagingRoot 'typescript'
$rustStage = Join-Path $stagingRoot 'rust'
$pythonStage = Join-Path $stagingRoot 'python'
$typescriptDestination = Join-Path $repositoryRoot 'packages\generated-client\src\generated'
$rustDestination = Join-Path $repositoryRoot 'crates\domain-contracts\src\generated'
$pythonDestination = Join-Path $repositoryRoot 'workers\contract-bindings\src'
$generatedManifestPath = Join-Path $repositoryRoot 'generated\contract-bindings-manifest.json'
$toolRoot = Join-Path $cacheRoot 'tools'
$vendoredProstArchive = Join-Path $repositoryRoot 'tools\vendor\protoc-gen-prost-0.5.0.crate'
$vendoredProstSha256 = '4018e7b5e3a213d241d79a0ef43a442a17dc23dcdd5b81b0c42b2549197897fd'
$vendoredProstWindowsBinary = Join-Path $repositoryRoot 'tools\vendor\protoc-gen-prost\windows-x86_64\protoc-gen-prost.exe'
$vendoredProstWindowsBinarySha256 = 'cfd828f8d2b98854bd69869353d0f72f2bbcfd28c2ee599060cdb86e31a9c4a3'
$prostExecutableName = if ($IsWindows -or $env:OS -eq 'Windows_NT') { 'protoc-gen-prost.exe' } else { 'protoc-gen-prost' }
$prostExecutable = Join-Path $toolRoot "bin\$prostExecutableName"
$expectedContractManifestSha256 = 'adbcba96ee023f886ba6ea8de0083d7f09c2f5db67b60ddd6db6b231932fbe66'

function Assert-UnderRepository {
    param([string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $prefix = $repositoryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "path escaped repository root: $fullPath"
    }
}

function Invoke-Checked {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$Failure
    )
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Failure (exit=$LASTEXITCODE)"
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [IO.File]::OpenRead($LiteralPath)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-RelativeFiles {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $normalizedRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    return @(
        Get-ChildItem -LiteralPath $normalizedRoot -Recurse -File |
            Where-Object {
                $_.Extension -ne '.pyc' -and
                $_.FullName -notmatch '[\\/]__pycache__[\\/]'
            } |
            ForEach-Object { $_.FullName.Substring($normalizedRoot.Length + 1).Replace('\', '/') } |
            Sort-Object
    )
}

function Compare-GeneratedTree {
    param(
        [string]$ExpectedRoot,
        [string]$ActualRoot,
        [string]$Label
    )
    if (-not (Test-Path -LiteralPath $ActualRoot)) {
        throw "$Label generated destination is missing: $ActualRoot; run pnpm run generate:contracts"
    }
    $expectedFiles = @(Get-RelativeFiles -Root $ExpectedRoot)
    $actualFiles = @(Get-RelativeFiles -Root $ActualRoot)
    $pathDifference = Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $actualFiles
    if ($null -ne $pathDifference) {
        $details = ($pathDifference | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join '; '
        throw "$Label generated file set drift: $details"
    }
    foreach ($relativePath in $expectedFiles) {
        $expectedPath = Join-Path $ExpectedRoot ($relativePath.Replace('/', '\'))
        $actualPath = Join-Path $ActualRoot ($relativePath.Replace('/', '\'))
        $expectedHash = Get-Sha256Hex -LiteralPath $expectedPath
        $actualHash = Get-Sha256Hex -LiteralPath $actualPath
        if ($expectedHash -ne $actualHash) {
            throw "$Label generated file digest drift: $relativePath"
        }
    }
}

function Replace-GeneratedTree {
    param(
        [string]$SourceRoot,
        [string]$DestinationRoot
    )
    Assert-UnderRepository -Path $DestinationRoot
    if (Test-Path -LiteralPath $DestinationRoot) {
        Remove-Item -LiteralPath $DestinationRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $SourceRoot -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $DestinationRoot -Recurse -Force
    }
}

function Get-ManifestEntries {
    param(
        [string]$SourceRoot,
        [string]$DestinationPrefix
    )
    $entries = @()
    foreach ($relativePath in Get-RelativeFiles -Root $SourceRoot) {
        $sourcePath = Join-Path $SourceRoot ($relativePath.Replace('/', '\'))
        $entries += [ordered]@{
            path = "$DestinationPrefix/$relativePath"
            sha256 = Get-Sha256Hex -LiteralPath $sourcePath
        }
    }
    return $entries
}

Assert-UnderRepository -Path $cacheRoot
Assert-UnderRepository -Path $typescriptDestination
Assert-UnderRepository -Path $rustDestination
Assert-UnderRepository -Path $pythonDestination

$contractManifestHash = Get-Sha256Hex -LiteralPath $contractManifestPath
if ($contractManifestHash -ne $expectedContractManifestSha256) {
    throw "contract manifest digest mismatch: $contractManifestHash"
}
$contractManifest = Get-Content -Raw -Encoding utf8 -LiteralPath $contractManifestPath | ConvertFrom-Json
$protoArtifacts = @(
    $contractManifest.artifacts |
        Where-Object { $_.path -like 'proto/*.proto' } |
        Sort-Object path
)
if ($protoArtifacts.Count -ne 9) {
    throw "expected 9 V-01 proto artifacts, found $($protoArtifacts.Count)"
}

Invoke-Checked -Executable 'node' -Arguments @((Join-Path $repositoryRoot 'scripts\verify-v01-contract-import.mjs')) -Failure 'V-01 import verification failed'

$bufExecutable = Join-Path $repositoryRoot 'node_modules\.bin\buf.CMD'
$protocGenEsExecutable = Join-Path $repositoryRoot 'node_modules\.bin\protoc-gen-es.CMD'
if (-not (Test-Path -LiteralPath $bufExecutable)) { throw 'Buf is missing; run pnpm install --frozen-lockfile' }
if (-not (Test-Path -LiteralPath $protocGenEsExecutable)) { throw 'protoc-gen-es is missing; run pnpm install --frozen-lockfile' }

if (-not (Test-Path -LiteralPath $prostExecutable)) {
    if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) {
        throw 'G4-01 protoc-gen-prost bootstrap currently supports only the accepted Windows x86_64 CI baseline'
    }
    $actualVendorHash = Get-Sha256Hex -LiteralPath $vendoredProstArchive
    if ($actualVendorHash -ne $vendoredProstSha256) {
        throw "vendored protoc-gen-prost archive digest mismatch: $actualVendorHash"
    }
    $actualBinaryHash = Get-Sha256Hex -LiteralPath $vendoredProstWindowsBinary
    if ($actualBinaryHash -ne $vendoredProstWindowsBinarySha256) {
        throw "vendored protoc-gen-prost binary digest mismatch: $actualBinaryHash"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $prostExecutable) -Force | Out-Null
    Copy-Item -LiteralPath $vendoredProstWindowsBinary -Destination $prostExecutable
}
$prostVersion = (& $prostExecutable --version).Trim()
if ($LASTEXITCODE -ne 0 -or $prostVersion -ne '0.5.0') {
    throw "unexpected protoc-gen-prost version: $prostVersion"
}

if (Test-Path -LiteralPath $stagingRoot) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $typescriptStage, $rustStage, $pythonStage -Force | Out-Null

$oldPath = $env:PATH
$oldBufCache = $env:BUF_CACHE_DIR
$oldUvCache = $env:UV_CACHE_DIR
$env:PATH = "$(Join-Path $repositoryRoot 'node_modules\.bin');$(Join-Path $toolRoot 'bin');$oldPath"
$env:BUF_CACHE_DIR = Join-Path $cacheRoot 'buf'
$env:UV_CACHE_DIR = Join-Path $cacheRoot 'uv'
try {
    $templatePath = Join-Path $cacheRoot 'buf.gen.yaml'
    $typescriptOutput = $typescriptStage.Substring($repositoryRoot.Length + 1).Replace('\', '/')
    $rustOutput = $rustStage.Substring($repositoryRoot.Length + 1).Replace('\', '/')
    $template = @"
version: v2
clean: true
plugins:
  - local: protoc-gen-es
    out: $typescriptOutput
    opt:
      - target=ts
      - import_extension=js
  - local: protoc-gen-prost
    out: $rustOutput
"@
    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($templatePath, $template.Replace("`r`n", "`n") + "`n", $utf8NoBom)

    $bufArguments = @('generate', '--template', $templatePath)
    foreach ($artifact in $protoArtifacts) {
        $bufArguments += @('--path', "contracts/$($artifact.path)")
    }
    Invoke-Checked -Executable $bufExecutable -Arguments $bufArguments -Failure 'Buf TypeScript/Rust generation failed'

    $pythonProtoFiles = @($protoArtifacts | ForEach-Object { $_.path.Substring('proto/'.Length) })
    $pythonArguments = @(
        'run', '--project', (Join-Path $contractsRoot 'toolchain\python'), '--frozen',
        'python', '-m', 'grpc_tools.protoc',
        '-I', (Join-Path $contractsRoot 'proto'),
        "--python_out=$pythonStage",
        "--pyi_out=$pythonStage"
    ) + $pythonProtoFiles
    Invoke-Checked -Executable 'uv' -Arguments $pythonArguments -Failure 'Python contract generation failed'
}
finally {
    $env:PATH = $oldPath
    $env:BUF_CACHE_DIR = $oldBufCache
    $env:UV_CACHE_DIR = $oldUvCache
}

# protoc-gen-es emits an additional blank line at EOF. Normalize this as part
# of the generator profile so checked-in output passes the repository's
# whitespace gate and remains byte-identical across clean checkouts.
foreach ($typescriptFile in Get-ChildItem -LiteralPath $typescriptStage -Recurse -Filter '*.ts' -File) {
    $typescriptText = [IO.File]::ReadAllText($typescriptFile.FullName)
    $typescriptText = $typescriptText.Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd([char[]]"`n") + "`n"
    [IO.File]::WriteAllText($typescriptFile.FullName, $typescriptText, $utf8NoBom)
}

$typescriptFiles = @(Get-ChildItem -LiteralPath $typescriptStage -Recurse -Filter '*.ts' -File)
$rustFiles = @(Get-ChildItem -LiteralPath $rustStage -Recurse -Filter '*.rs' -File)
$pythonModules = @(Get-ChildItem -LiteralPath $pythonStage -Recurse -Filter '*_pb2.py' -File)
$pythonStubs = @(Get-ChildItem -LiteralPath $pythonStage -Recurse -Filter '*_pb2.pyi' -File)
if ($typescriptFiles.Count -ne 9 -or $rustFiles.Count -ne 9 -or $pythonModules.Count -ne 9 -or $pythonStubs.Count -ne 9) {
    throw "unexpected generated counts: ts=$($typescriptFiles.Count) rust=$($rustFiles.Count) python=$($pythonModules.Count) pyi=$($pythonStubs.Count)"
}

$generatedEntries = @()
$generatedEntries += Get-ManifestEntries -SourceRoot $typescriptStage -DestinationPrefix 'packages/generated-client/src/generated'
$generatedEntries += Get-ManifestEntries -SourceRoot $rustStage -DestinationPrefix 'crates/domain-contracts/src/generated'
$generatedEntries += Get-ManifestEntries -SourceRoot $pythonStage -DestinationPrefix 'workers/contract-bindings/src'
$generatedEntries = @($generatedEntries | Sort-Object { $_.path })
$generatedManifest = [ordered]@{
    schemaVersion = 'egopulse-generated-contract-bindings/v0.1'
    sourceManifestSha256 = $expectedContractManifestSha256
    generators = [ordered]@{
        buf = '1.72.0'
        protocGenEs = '2.14.0'
        protocGenProst = '0.5.0'
        grpcioTools = '1.83.0'
        protobufPython = '7.35.1'
    }
    fileCount = $generatedEntries.Count
    files = $generatedEntries
}
$generatedManifestText = ($generatedManifest | ConvertTo-Json -Depth 8) + "`n"

if ($Mode -eq 'Write') {
    Replace-GeneratedTree -SourceRoot $typescriptStage -DestinationRoot $typescriptDestination
    Replace-GeneratedTree -SourceRoot $rustStage -DestinationRoot $rustDestination
    Replace-GeneratedTree -SourceRoot $pythonStage -DestinationRoot $pythonDestination
    $generatedManifestDirectory = Split-Path -Parent $generatedManifestPath
    New-Item -ItemType Directory -Path $generatedManifestDirectory -Force | Out-Null
    [IO.File]::WriteAllText($generatedManifestPath, $generatedManifestText.Replace("`r`n", "`n"), $utf8NoBom)
    Write-Output "contract_codegen=written files=$($generatedEntries.Count)"
} else {
    Compare-GeneratedTree -ExpectedRoot $typescriptStage -ActualRoot $typescriptDestination -Label 'TypeScript'
    Compare-GeneratedTree -ExpectedRoot $rustStage -ActualRoot $rustDestination -Label 'Rust'
    Compare-GeneratedTree -ExpectedRoot $pythonStage -ActualRoot $pythonDestination -Label 'Python'
    if (-not (Test-Path -LiteralPath $generatedManifestPath)) {
        throw 'generated contract manifest is missing; run pnpm run generate:contracts'
    }
    $actualManifestText = Get-Content -Raw -Encoding utf8 -LiteralPath $generatedManifestPath
    if ($actualManifestText.Replace("`r`n", "`n") -ne $generatedManifestText.Replace("`r`n", "`n")) {
        throw 'generated contract manifest drift; run pnpm run generate:contracts'
    }
    Write-Output "contract_codegen=clean files=$($generatedEntries.Count)"
}
