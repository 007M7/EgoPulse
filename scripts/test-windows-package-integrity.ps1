param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'windows-package-integrity.ps1')

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Pattern, [string]$Label)
    try {
        & $Action
    }
    catch {
        if ($Pattern -and $_.Exception.Message -notmatch $Pattern) {
            throw "$Label failed with unexpected error: $($_.Exception.Message)"
        }
        return
    }
    throw "$Label unexpectedly succeeded"
}

function Write-TestText {
    param([string]$Path, [string]$Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        $null = New-Item -ItemType Directory -Force -Path $parent
    }
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Write-TestManifest {
    param([string]$PackageRoot)
    $manifest = Join-Path $PackageRoot 'SHA256SUMS'
    if (Test-Path -LiteralPath $manifest) { Remove-Item -LiteralPath $manifest -Force }
    $lines = @(Get-EgoPulsePackageFileInventory -PackageRoot $PackageRoot | ForEach-Object {
        "$(Get-EgoPulseSha256Hex -LiteralPath $_.FullPath)  $($_.Path)"
    })
    [IO.File]::WriteAllLines($manifest, $lines, [Text.Encoding]::ASCII)
}

function New-TestPackage {
    param([string]$Path)
    $null = New-Item -ItemType Directory -Path $Path
    Write-TestText -Path (Join-Path $Path 'config/agentos-config.example.json') -Value '{"fixture":true}'
    Write-TestText -Path (Join-Path $Path 'bin/payload.txt') -Value ('package-payload-' * 32)
    Write-TestText -Path (Join-Path $Path 'BUILD-METADATA.json') -Value '{"classification":"unsigned-release-candidate","platform":"windows-x86_64","surfaces":["cli","tui"]}'
    Write-TestManifest -PackageRoot $Path
    return $Path
}

function Copy-TestPackage {
    param([string]$Source, [string]$Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse
    return $Destination
}

function New-TestZipFromPackage {
    param(
        [string]$PackageRoot,
        [string]$ArchivePath,
        [string[]]$OmitPaths = @(),
        [hashtable]$AdditionalEntries = @{}
    )
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $top = Split-Path -Leaf $PackageRoot
            $null = $archive.CreateEntry("$top/")
            foreach ($file in Get-EgoPulsePackageFileInventory -PackageRoot $PackageRoot) {
                if ($OmitPaths -contains $file.Path) { continue }
                $entry = $archive.CreateEntry("$top/$($file.Path)", [IO.Compression.CompressionLevel]::Optimal)
                $input = [IO.File]::OpenRead($file.FullPath)
                $output = $entry.Open()
                try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
            }
            foreach ($entryName in $AdditionalEntries.Keys) {
                $entry = $archive.CreateEntry([string]$entryName, [IO.Compression.CompressionLevel]::Optimal)
                $output = $entry.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$AdditionalEntries[$entryName])
                    $output.Write($bytes, 0, $bytes.Length)
                }
                finally { $output.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return $ArchivePath
}

function New-CustomZip {
    param([string]$ArchivePath, [object[]]$Entries)
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($definition in $Entries) {
                $entry = $archive.CreateEntry([string]$definition.Path, [IO.Compression.CompressionLevel]::Optimal)
                if ($definition.ContainsKey('Link') -and $definition.Link) {
                    $entry.ExternalAttributes = [Convert]::ToInt32('A0000000', 16)
                }
                if (-not ($definition.ContainsKey('Directory') -and $definition.Directory)) {
                    $output = $entry.Open()
                    try {
                        $bytes = [Text.Encoding]::UTF8.GetBytes([string]$definition.Content)
                        $output.Write($bytes, 0, $bytes.Length)
                    }
                    finally { $output.Dispose() }
                }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return $ArchivePath
}

function Assert-ArchiveRejected {
    param([string]$ArchivePath, [string]$TopLevel, [string]$Pattern, [hashtable]$Limits = @{})
    $digest = Get-EgoPulseSha256Hex -LiteralPath $ArchivePath
    Assert-Throws -Label "archive $Pattern" -Pattern $Pattern -Action {
        Test-EgoPulseArchiveEnvelope -ArchivePath $ArchivePath -ExpectedArchiveSha256 $digest -ExpectedTopLevel $TopLevel @Limits
    }
}

function Assert-ConcurrentPublicTreeCopyIsExclusive {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    $libraryPath = (Resolve-Path (Join-Path $PSScriptRoot 'windows-package-integrity.ps1')).Path
    $startGate = [Threading.ManualResetEventSlim]::new($false)
    $readyGate = [Threading.CountdownEvent]::new(2)
    $workers = @()
    try {
        foreach ($workerId in 1..2) {
            $shell = [PowerShell]::Create()
            $null = $shell.AddScript({
                param($LibraryPath, $Source, $Destination, $Ready, $Start, $WorkerId)
                . $LibraryPath
                $null = $Ready.Signal()
                $Start.Wait()
                try {
                    $null = Copy-EgoPulsePublicTreeExclusively -SourceRoot $Source -DestinationRoot $Destination
                    [pscustomobject]@{ WorkerId = $WorkerId; Succeeded = $true; Error = '' }
                }
                catch {
                    [pscustomobject]@{ WorkerId = $WorkerId; Succeeded = $false; Error = $_.Exception.Message }
                }
            })
            $null = $shell.AddArgument($libraryPath)
            $null = $shell.AddArgument($SourceRoot)
            $null = $shell.AddArgument($DestinationRoot)
            $null = $shell.AddArgument($readyGate)
            $null = $shell.AddArgument($startGate)
            $null = $shell.AddArgument($workerId)
            $workers += [pscustomobject]@{ Shell = $shell; Async = $shell.BeginInvoke() }
        }
        if (-not $readyGate.Wait([TimeSpan]::FromSeconds(10))) {
            throw 'Concurrent public-tree copy workers did not reach the deterministic start gate.'
        }
        $startGate.Set()
        $results = @($workers | ForEach-Object { @($_.Shell.EndInvoke($_.Async)) })
        $successes = @($results | Where-Object { $_.Succeeded })
        $failures = @($results | Where-Object { -not $_.Succeeded })
        Assert-Condition ($successes.Count -eq 1) 'Concurrent public-tree copy did not have exactly one winner.'
        Assert-Condition ($failures.Count -eq 1) 'Concurrent public-tree copy did not reject exactly one contender.'
        Assert-Condition `
            ($failures[0].Error -match '\AExclusive directory creation failed:') `
            "Concurrent public-tree loser did not fail on atomic exclusive destination creation: $($failures[0].Error)"
    }
    finally {
        $startGate.Set()
        foreach ($worker in $workers) { $worker.Shell.Dispose() }
        $readyGate.Dispose()
        $startGate.Dispose()
    }
}

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$testRoot = Join-Path $temporaryBase "egopulse-package-integrity-test-$([Guid]::NewGuid().ToString('N'))"
$originalPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
$originalUserConfig = [Environment]::GetEnvironmentVariable('EGOPULSE_USER_CONFIG', 'Process')
try {
    $null = New-Item -ItemType Directory -Path $testRoot
    $happy = New-TestPackage -Path (Join-Path $testRoot 'fixture-package')
    $manifestResult = Test-EgoPulsePackageManifest -PackageRoot $happy
    Assert-Condition ($manifestResult.Entries.Count -eq 3) 'happy manifest did not cover every non-manifest file'
    $happyZip = New-TestZipFromPackage -PackageRoot $happy -ArchivePath (Join-Path $testRoot 'happy.zip')
    $happyDigest = Get-EgoPulseSha256Hex -LiteralPath $happyZip
    $preflight = Test-EgoPulseArchiveEnvelope -ArchivePath $happyZip -ExpectedArchiveSha256 $happyDigest -ExpectedTopLevel 'fixture-package'
    Assert-Condition ($preflight.EntryCount -eq 5) 'happy ZIP entry count is unexpected'
    $extracted = Expand-EgoPulseArchiveSafely -ArchivePath $happyZip -ExpectedArchiveSha256 $happyDigest -ExpectedTopLevel 'fixture-package'
    try { Compare-EgoPulsePackageTrees -SourceRoot $happy -ExtractedRoot $extracted.PackageRoot }
    finally { Remove-EgoPulseVerificationTemporaryRoot -TemporaryRoot $extracted.TemporaryRoot }

    Assert-Throws {
        ConvertTo-EgoPulsePackagePath -Path ((1..65 | ForEach-Object { 's' }) -join '/')
    } '64-segment limit' 'package path segment-count limit'
    Assert-Throws {
        ConvertTo-EgoPulsePackagePath -Path (([string][char]0x754c) * 86)
    } '255-byte UTF-8 limit' 'package path segment byte limit'
    Assert-Throws {
        ConvertTo-EgoPulsePackagePath -Path ((1..6 | ForEach-Object { 'p' * 200 }) -join '/')
    } '1024-byte UTF-8 limit' 'package path total byte limit'

    $extraManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'manifest-extra')
    Add-Content -LiteralPath (Join-Path $extraManifest 'SHA256SUMS') -Value "$('0' * 64)  ghost.txt" -Encoding ascii
    Assert-Throws { Test-EgoPulsePackageManifest $extraManifest } 'path set is not closed' 'manifest extra path'

    $missingManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'manifest-missing')
    $missingLines = @(Get-Content -LiteralPath (Join-Path $missingManifest 'SHA256SUMS')) | Select-Object -Skip 1
    [IO.File]::WriteAllLines((Join-Path $missingManifest 'SHA256SUMS'), $missingLines, [Text.Encoding]::ASCII)
    Assert-Throws { Test-EgoPulsePackageManifest $missingManifest } 'path set is not closed' 'manifest missing path'

    $duplicateManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'manifest-duplicate')
    $firstLine = Get-Content -LiteralPath (Join-Path $duplicateManifest 'SHA256SUMS') | Select-Object -First 1
    Add-Content -LiteralPath (Join-Path $duplicateManifest 'SHA256SUMS') -Value $firstLine -Encoding ascii
    Assert-Throws { Test-EgoPulsePackageManifest $duplicateManifest } 'duplicate path' 'manifest duplicate path'

    $caseManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'manifest-case')
    $caseLine = Get-Content -LiteralPath (Join-Path $caseManifest 'SHA256SUMS') | Select-Object -First 1
    $caseParts = $caseLine -split '  ', 2
    Add-Content -LiteralPath (Join-Path $caseManifest 'SHA256SUMS') -Value "$($caseParts[0])  $($caseParts[1].ToUpperInvariant())" -Encoding ascii
    Assert-Throws { Test-EgoPulsePackageManifest $caseManifest } 'OrdinalIgnoreCase' 'manifest case collision'

    foreach ($unsafePath in @('/absolute.txt', '//server/share.txt', '../traversal.txt', 'dir//empty.txt', 'C:/drive.txt', 'file.txt:stream', 'CON.txt')) {
        $unsafeManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot "manifest-unsafe-$([Guid]::NewGuid().ToString('N'))")
        Add-Content -LiteralPath (Join-Path $unsafeManifest 'SHA256SUMS') -Value "$('0' * 64)  $unsafePath" -Encoding ascii
        Assert-Throws { Test-EgoPulsePackageManifest $unsafeManifest } 'absolute|traversal|empty|ADS|reserved' "manifest unsafe path $unsafePath"
    }

    $selfManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'manifest-self')
    Add-Content -LiteralPath (Join-Path $selfManifest 'SHA256SUMS') -Value "$('0' * 64)  SHA256SUMS" -Encoding ascii
    Assert-Throws { Test-EgoPulsePackageManifest $selfManifest } 'must not list itself' 'manifest self listing'

    $hashManifest = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'manifest-hash')
    $hashLines = @(Get-Content -LiteralPath (Join-Path $hashManifest 'SHA256SUMS'))
    $hashLines[0] = ('0' * 64) + $hashLines[0].Substring(64)
    [IO.File]::WriteAllLines((Join-Path $hashManifest 'SHA256SUMS'), $hashLines, [Text.Encoding]::ASCII)
    Assert-Throws { Test-EgoPulsePackageManifest $hashManifest } 'SHA-256 mismatch' 'manifest hash mismatch'

    $requiredMissing = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'required-missing')
    Remove-Item -LiteralPath (Join-Path $requiredMissing 'config/agentos-config.example.json') -Force
    Write-TestManifest -PackageRoot $requiredMissing
    Assert-Throws { Test-EgoPulsePackageManifest $requiredMissing } 'Required package file is missing' 'required config missing'

    $hardLinkPackage = Copy-TestPackage -Source $happy -Destination (Join-Path $testRoot 'hardlink-package')
    $hardLink = Join-Path $hardLinkPackage 'bin/payload-hardlink.txt'
    $null = New-Item -ItemType HardLink -Path $hardLink -Target (Join-Path $hardLinkPackage 'bin/payload.txt')
    Assert-Throws { Get-EgoPulsePackageFileInventory $hardLinkPackage } 'exactly one link' 'package hard link'
    $ordinaryFile = Get-Item -LiteralPath (Join-Path $happy 'bin/payload.txt')
    Assert-Throws {
        Assert-EgoPulseSingleLinkFile -File $ordinaryFile -LinkCountReader { throw 'simulated link-count failure' }
    } 'Unable to prove.*simulated link-count failure' 'package link count read failure'

    $exclusiveRoot = Join-Path $testRoot 'exclusive-root'
    $null = New-EgoPulseExclusiveDirectory -LiteralPath $exclusiveRoot
    Assert-Condition (Test-Path -LiteralPath $exclusiveRoot -PathType Container) 'exclusive directory was not created'
    Assert-Throws { New-EgoPulseExclusiveDirectory -LiteralPath $exclusiveRoot } '\AExclusive directory creation failed:' 'pre-existing candidate root'
    $exclusiveZip = Join-Path $testRoot 'exclusive.zip'
    $exclusiveZipStream = Open-EgoPulseExclusiveFile -LiteralPath $exclusiveZip
    $exclusiveZipStream.Dispose()
    Assert-Throws { Open-EgoPulseExclusiveFile -LiteralPath $exclusiveZip } '\AExclusive file creation failed:' 'pre-existing candidate ZIP'
    $exclusiveHash = Join-Path $testRoot 'exclusive.zip.sha256'
    $exclusiveHashStream = Open-EgoPulseExclusiveFile -LiteralPath $exclusiveHash
    $exclusiveHashStream.Dispose()
    Assert-Throws { Open-EgoPulseExclusiveFile -LiteralPath $exclusiveHash } '\AExclusive file creation failed:' 'pre-existing candidate hash'
    $exclusiveArchive = Join-Path $testRoot 'exclusive-package.zip'
    $null = New-EgoPulsePackageArchiveExclusively -PackageRoot $happy -ArchivePath $exclusiveArchive
    Assert-Condition (Test-Path -LiteralPath $exclusiveArchive -PathType Leaf) 'exclusive package archive was not created'
    Assert-Throws {
        New-EgoPulsePackageArchiveExclusively -PackageRoot $happy -ArchivePath $exclusiveArchive
    } '\AExclusive file creation failed:' 'exclusive package archive overwrite'

    $publicSource = Join-Path $testRoot 'public-source'
    $null = New-Item -ItemType Directory -Path (Join-Path $publicSource 'nested') -Force
    Write-TestText -Path (Join-Path $publicSource 'nested/payload.txt') -Value 'public-tree-payload'
    $publicDestination = Join-Path $testRoot 'public-destination'
    $null = Copy-EgoPulsePublicTreeExclusively -SourceRoot $publicSource -DestinationRoot $publicDestination
    Assert-Condition ((Get-Content -Raw -LiteralPath (Join-Path $publicDestination 'nested/payload.txt')) -ceq 'public-tree-payload') 'exclusive public-tree copy changed file content'
    Assert-Throws {
        Copy-EgoPulsePublicTreeExclusively -SourceRoot $publicSource -DestinationRoot $publicDestination
    } '\AExclusive directory creation failed:' 'pre-existing public-tree destination pollution'
    $preExistingTarget = Join-Path $testRoot 'pre-existing-target.txt'
    Write-TestText -Path $preExistingTarget -Value 'attacker-content'
    Assert-Throws {
        Copy-EgoPulseFileExclusively `
            -SourcePath (Join-Path $publicSource 'nested/payload.txt') `
            -DestinationPath $preExistingTarget
    } '\AExclusive file creation failed:' 'pre-existing packager target file pollution'
    Assert-Condition ((Get-Content -Raw -LiteralPath $preExistingTarget) -ceq 'attacker-content') 'exclusive packager file copy overwrote a pre-existing target'
    Assert-ConcurrentPublicTreeCopyIsExclusive `
        -SourceRoot $publicSource `
        -DestinationRoot (Join-Path $testRoot 'public-concurrent-destination')

    Assert-Throws { Assert-EgoPulseArchiveArguments -ArchivePath $happyZip } 'provided together' 'expected digest missing'
    Assert-Throws { Assert-EgoPulseArchiveArguments -ExpectedArchiveSha256 ('a' * 64) } 'provided together' 'archive path missing'
    Assert-Throws { Assert-EgoPulseArchiveArguments -ArchivePath $happyZip -ExpectedArchiveSha256 'abcd' } 'exactly 64' 'expected digest malformed'
    $notZip = Join-Path $testRoot 'not-a-zip.bin'
    Write-TestText -Path $notZip -Value 'not a zip'
    Assert-Throws {
        Test-EgoPulseArchiveEnvelope -ArchivePath $notZip -ExpectedArchiveSha256 ('0' * 64) -ExpectedTopLevel 'fixture-package'
    } 'Archive SHA-256 mismatch' 'whole archive hash precedes ZIP open'

    Assert-ArchiveRejected -ArchivePath $happyZip -TopLevel 'wrong-top' -Pattern 'top-level'
    Assert-ArchiveRejected -ArchivePath $happyZip -TopLevel 'fixture-package' -Pattern 'entry count' -Limits @{ MaximumEntryCount = 1 }
    Assert-ArchiveRejected -ArchivePath $happyZip -TopLevel 'fixture-package' -Pattern 'single-file' -Limits @{ MaximumSingleExpandedBytes = 1 }
    Assert-ArchiveRejected -ArchivePath $happyZip -TopLevel 'fixture-package' -Pattern 'total expansion' -Limits @{ MaximumTotalExpandedBytes = 1 }
    Assert-ArchiveRejected -ArchivePath $happyZip -TopLevel 'fixture-package' -Pattern 'compression-ratio' -Limits @{ MaximumCompressionRatio = 1.0 }

    $duplicateZip = New-CustomZip -ArchivePath (Join-Path $testRoot 'duplicate.zip') -Entries @(
        @{ Path = 'fixture-package/a.txt'; Content = 'a' },
        @{ Path = 'fixture-package/a.txt'; Content = 'b' }
    )
    Assert-ArchiveRejected $duplicateZip 'fixture-package' 'duplicate path'
    $caseZip = New-CustomZip -ArchivePath (Join-Path $testRoot 'case.zip') -Entries @(
        @{ Path = 'fixture-package/a.txt'; Content = 'a' },
        @{ Path = 'fixture-package/A.txt'; Content = 'b' }
    )
    Assert-ArchiveRejected $caseZip 'fixture-package' 'OrdinalIgnoreCase'
    foreach ($unsafeZipPath in @(
        '/absolute.txt',
        '//server/share.txt',
        'fixture-package/../traversal.txt',
        'fixture-package/dir//empty.txt',
        'fixture-package/file.txt:stream',
        'fixture-package/NUL.txt',
        'C:/drive.txt'
    )) {
        $unsafeZip = New-CustomZip -ArchivePath (Join-Path $testRoot "unsafe-$([Guid]::NewGuid().ToString('N')).zip") -Entries @(
            @{ Path = $unsafeZipPath; Content = 'x' }
        )
        Assert-ArchiveRejected $unsafeZip 'fixture-package' 'absolute|traversal|empty|ADS|reserved|top-level'
    }
    $linkZip = New-CustomZip -ArchivePath (Join-Path $testRoot 'link.zip') -Entries @(
        @{ Path = 'fixture-package/link'; Content = 'target'; Link = $true }
    )
    Assert-ArchiveRejected $linkZip 'fixture-package' 'not a regular file'

    $pathTreeCases = @(
        @{
            Name = 'file-before-child'
            Entries = @(
                @{ Path = 'fixture-package/node'; Content = 'file' },
                @{ Path = 'fixture-package/node/child.txt'; Content = 'child' }
            )
            Pattern = 'file/directory conflict'
        },
        @{
            Name = 'child-before-file'
            Entries = @(
                @{ Path = 'fixture-package/node/child.txt'; Content = 'child' },
                @{ Path = 'fixture-package/node'; Content = 'file' }
            )
            Pattern = 'file/directory conflict'
        },
        @{
            Name = 'explicit-directory-before-file'
            Entries = @(
                @{ Path = 'fixture-package/node/'; Directory = $true },
                @{ Path = 'fixture-package/node'; Content = 'file' }
            )
            Pattern = 'file/directory conflict'
        },
        @{
            Name = 'file-before-explicit-directory'
            Entries = @(
                @{ Path = 'fixture-package/node'; Content = 'file' },
                @{ Path = 'fixture-package/node/'; Directory = $true }
            )
            Pattern = 'file/directory conflict'
        },
        @{
            Name = 'implicit-ancestor-case-drift'
            Entries = @(
                @{ Path = 'fixture-package/Parent/first.txt'; Content = 'first' },
                @{ Path = 'fixture-package/parent/second.txt'; Content = 'second' }
            )
            Pattern = 'OrdinalIgnoreCase ancestor collision'
        },
        @{
            Name = 'explicit-ancestor-case-drift'
            Entries = @(
                @{ Path = 'fixture-package/Parent/'; Directory = $true },
                @{ Path = 'fixture-package/parent/child.txt'; Content = 'child' }
            )
            Pattern = 'OrdinalIgnoreCase ancestor collision'
        }
    )
    foreach ($pathTreeCase in $pathTreeCases) {
        $pathTreeZip = New-CustomZip `
            -ArchivePath (Join-Path $testRoot "$($pathTreeCase.Name).zip") `
            -Entries $pathTreeCase.Entries
        Assert-ArchiveRejected $pathTreeZip 'fixture-package' $pathTreeCase.Pattern
    }

    $extraZip = New-TestZipFromPackage -PackageRoot $happy -ArchivePath (Join-Path $testRoot 'extra.zip') -AdditionalEntries @{
        'fixture-package/extra.txt' = 'extra'
    }
    $extraExtracted = Expand-EgoPulseArchiveSafely -ArchivePath $extraZip -ExpectedArchiveSha256 (Get-EgoPulseSha256Hex $extraZip) -ExpectedTopLevel 'fixture-package'
    try { Assert-Throws { Compare-EgoPulsePackageTrees $happy $extraExtracted.PackageRoot } 'path set is not closed|counts differ' 'ZIP extra file' }
    finally { Remove-EgoPulseVerificationTemporaryRoot $extraExtracted.TemporaryRoot }
    $missingZip = New-TestZipFromPackage -PackageRoot $happy -ArchivePath (Join-Path $testRoot 'missing.zip') -OmitPaths @('bin/payload.txt')
    $missingExtracted = Expand-EgoPulseArchiveSafely -ArchivePath $missingZip -ExpectedArchiveSha256 (Get-EgoPulseSha256Hex $missingZip) -ExpectedTopLevel 'fixture-package'
    try { Assert-Throws { Compare-EgoPulsePackageTrees $happy $missingExtracted.PackageRoot } 'path set is not closed|missing' 'ZIP missing file' }
    finally { Remove-EgoPulseVerificationTemporaryRoot $missingExtracted.TemporaryRoot }

    [Environment]::SetEnvironmentVariable('PYTHONPATH', 'before-python', 'Process')
    [Environment]::SetEnvironmentVariable('EGOPULSE_USER_CONFIG', 'before-config', 'Process')
    Invoke-EgoPulseRestoredEnvironment {
        $env:PYTHONPATH = 'changed-python'
        $env:EGOPULSE_USER_CONFIG = 'changed-config'
    }
    Assert-Condition ($env:PYTHONPATH -ceq 'before-python' -and $env:EGOPULSE_USER_CONFIG -ceq 'before-config') 'environment was not restored after success'
    Assert-Throws {
        Invoke-EgoPulseRestoredEnvironment {
            $env:PYTHONPATH = 'failed-python'
            Remove-Item Env:EGOPULSE_USER_CONFIG
            throw 'intentional-environment-failure'
        }
    } 'intentional-environment-failure' 'environment failure propagation'
    Assert-Condition ($env:PYTHONPATH -ceq 'before-python' -and $env:EGOPULSE_USER_CONFIG -ceq 'before-config') 'environment was not restored after failure'

    [Environment]::SetEnvironmentVariable('PYTHONPATH', $null, 'Process')
    [Environment]::SetEnvironmentVariable('EGOPULSE_USER_CONFIG', $null, 'Process')
    Invoke-EgoPulseRestoredEnvironment {
        $env:PYTHONPATH = 'temporary-python'
        $env:EGOPULSE_USER_CONFIG = 'temporary-config'
    }
    Assert-Condition (-not (Test-Path Env:PYTHONPATH) -and -not (Test-Path Env:EGOPULSE_USER_CONFIG)) 'absent environment variables were not restored after success'
    Assert-Throws {
        Invoke-EgoPulseRestoredEnvironment {
            $env:PYTHONPATH = 'temporary-failure-python'
            $env:EGOPULSE_USER_CONFIG = 'temporary-failure-config'
            throw 'intentional-absent-environment-failure'
        }
    } 'intentional-absent-environment-failure' 'absent environment failure propagation'
    Assert-Condition (-not (Test-Path Env:PYTHONPATH) -and -not (Test-Path Env:EGOPULSE_USER_CONFIG)) 'absent environment variables were not restored after failure'

    Write-Output 'windows_package_integrity_test=passed'
}
finally {
    [Environment]::SetEnvironmentVariable('PYTHONPATH', $originalPythonPath, 'Process')
    [Environment]::SetEnvironmentVariable('EGOPULSE_USER_CONFIG', $originalUserConfig, 'Process')
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $testRoot).Path).TrimEnd('\', '/')
        $expectedPrefix = "$temporaryBase\egopulse-package-integrity-test-"
        if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolved) -notmatch '\Aegopulse-package-integrity-test-[0-9a-f]{32}\z') {
            throw "Refusing to remove unexpected integrity-test root: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
