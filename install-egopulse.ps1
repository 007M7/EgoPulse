param(
    [string]$PackageRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'EgoPulse'),
    [switch]$Force,
    [switch]$SkipMemoryWorker,
    [switch]$Launch,
    [switch]$NoPersistEnvironment
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-RandomHex {
    param([int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Set-UserEnvironment {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Set-Item -Path "Env:$Name" -Value $Value
    if (-not $NoPersistEnvironment) {
        [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
    }
}

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object]$Value
    )

    $property = $Object.PSObject.Properties[$Name]
    if (-not $property) {
        throw "Expected configuration property is missing: $Name"
    }
    $property.Value = $Value
}

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'EgoPulse first release supports Windows x64 only.'
}

foreach ($binary in @('agentosd.exe', 'egopulse.exe', 'egopulse-tui.exe')) {
    $path = Join-Path $root "bin/$binary"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Package binary is missing: $path"
    }
}

$uv = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uv) {
    throw 'uv is required. Install uv from https://docs.astral.sh/uv/ and rerun install-egopulse.ps1.'
}

$data = (New-Item -ItemType Directory -Force -Path $DataRoot).FullName
$configPath = Join-Path $data 'agentos-config.json'
$templatePath = Join-Path $root 'config/agentos-config.example.json'
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
    throw "Configuration template is missing: $templatePath"
}

if ((Test-Path -LiteralPath $configPath -PathType Leaf) -and -not $Force) {
    Write-Output "configuration=kept path=$configPath"
}
else {
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        Copy-Item -LiteralPath $configPath -Destination "$configPath.$([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')).bak"
    }
    $installationId = [Guid]::NewGuid().ToString('N')
    $principalId = "local-user:$($env:COMPUTERNAME.ToLowerInvariant())"
    $json = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
    $json = $json.Replace('local-user:replace-me', $principalId)
    $json = $json -replace 'replace-[A-Za-z0-9-]+', "egopulse-$installationId"
    $config = $json | ConvertFrom-Json

    foreach ($storeName in @('task', 'memory', 'artifact', 'verification', 'policy', 'verdict', 'adapter', 'collaboration')) {
        $store = $config.stores.PSObject.Properties[$storeName].Value
        Set-JsonProperty -Object $store -Name 'store_epoch' -Value "egopulse-$storeName-$installationId"
        if ($store.PSObject.Properties['database_path']) {
            $store.database_path = Join-Path $data "$storeName.db"
        }
        if ($store.PSObject.Properties['blob_root']) {
            $store.blob_root = Join-Path $data 'artifact-blobs'
        }
    }

    $config.identity.os_fingerprint_hex = New-RandomHex
    $config.identity.principal_id = $principalId
    $config.founder.allowed_founder_principal_ids = @($principalId)
    $config.memory_retrieval.principal_scope_allowlist = [pscustomobject]@{}
    $config.memory_retrieval.principal_scope_allowlist | Add-Member -NotePropertyName $principalId -NotePropertyValue @('scope:founder')

    $worker = Join-Path $root 'workers/memory-rag/.venv/Scripts/python.exe'
    $bindings = Join-Path $root 'workers/contract-bindings/src'
    $memorySource = Join-Path $root 'workers/memory-rag/src'
    $config.memory_retrieval.worker_executable = $worker
    $config.memory_retrieval.working_directory = $root
    $config.memory_retrieval.environment_overrides.PYTHONPATH = "$memorySource;$bindings"

    $configJson = $config | ConvertTo-Json -Depth 100
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($configPath, $configJson, $utf8NoBom)
    Write-Output "configuration=created path=$configPath"
}

$authorityKeys = @(
    'EGOPULSE_TASK_KEY_HEX',
    'EGOPULSE_MEMORY_KEY_HEX',
    'EGOPULSE_ARTIFACT_KEY_HEX',
    'EGOPULSE_VERIFICATION_KEY_HEX',
    'EGOPULSE_POLICY_KEY_HEX',
    'EGOPULSE_VERDICT_KEY_HEX',
    'EGOPULSE_ADAPTER_KEY_HEX',
    'EGOPULSE_COLLABORATION_KEY_HEX',
    'EGOPULSE_READ_MODEL_KEY_HEX',
    'EGOPULSE_TOKEN_MAC_KEY_HEX'
)
foreach ($keyName in $authorityKeys) {
    $existing = [Environment]::GetEnvironmentVariable($keyName, 'User')
    if ([string]::IsNullOrWhiteSpace($existing)) {
        Set-UserEnvironment -Name $keyName -Value (New-RandomHex)
    }
    else {
        Set-Item -Path "Env:$keyName" -Value $existing
    }
}
Set-UserEnvironment -Name 'EGOPULSE_USER_CONFIG' -Value $configPath
Set-UserEnvironment -Name 'EGOPULSE_IPC_INSTANCE' -Value 'default'
$runtimeConfig = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
$taskEpoch = [string]$runtimeConfig.stores.task.store_epoch
if ([string]::IsNullOrWhiteSpace($taskEpoch)) {
    throw 'Installed configuration is missing stores.task.store_epoch.'
}
$readModelEpoch = $taskEpoch -replace '^egopulse-task-', 'egopulse-read-model-'
Set-UserEnvironment -Name 'EGOPULSE_READ_MODEL_DB' -Value (Join-Path $data 'read-model.db')
Set-UserEnvironment -Name 'EGOPULSE_READ_MODEL_EPOCH' -Value $readModelEpoch

if (-not $SkipMemoryWorker) {
    & (Join-Path $root 'setup-memory-worker.ps1') -PackageRoot $root
    if ($LASTEXITCODE -ne 0) {
        throw "Memory Worker setup failed with exit code $LASTEXITCODE"
    }
}

$daemon = Join-Path $root 'bin/agentosd.exe'
& $daemon --check-config
if ($LASTEXITCODE -ne 0) {
    throw "EgoPulse configuration check failed with exit code $LASTEXITCODE"
}

if ($Launch) {
    Start-Process -FilePath $daemon -WorkingDirectory $root
    Write-Output 'agentosd=launched'
}

Write-Output 'egopulse_installation=passed'
Write-Output "package_root=$root"
Write-Output "data_root=$data"
Write-Output 'next=Open a new PowerShell window, then run egopulse.exe status or egopulse-tui.exe'
