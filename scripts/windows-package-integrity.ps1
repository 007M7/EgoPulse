$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (-not ('EgoPulseWindowsFileLinkInspector' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class EgoPulseWindowsFileLinkInspector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(
        string path,
        IntPtr securityAttributes);

    public static void CreateDirectoryExclusive(string path)
    {
        if (!CreateDirectoryW(path, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create exclusive package directory");
        }
    }

    public static uint GetNumberOfLinks(string path)
    {
        using (SafeFileHandle handle = CreateFileW(
            path,
            0,
            FileShare.Read | FileShare.Write | FileShare.Delete,
            IntPtr.Zero,
            FileMode.Open,
            0,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open package file metadata handle");
            }
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read package file link count");
            }
            return information.NumberOfLinks;
        }
    }
}
'@
}

function Get-EgoPulseSha256Hex {
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

function ConvertTo-EgoPulsePackagePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowDirectorySuffix
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.IndexOf([char]0) -ge 0) {
        throw 'Package path must be a non-empty relative path.'
    }
    foreach ($character in $Path.ToCharArray()) {
        if ([char]::IsControl($character)) {
            throw "Package path contains a control character: $Path"
        }
    }
    $normalized = $Path.Replace('\', '/')
    if ($AllowDirectorySuffix -and $normalized.EndsWith('/', [StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(0, $normalized.Length - 1)
    }
    if ([string]::IsNullOrWhiteSpace($normalized) -or
        $normalized.StartsWith('/', [StringComparison]::Ordinal) -or
        $normalized.StartsWith('//', [StringComparison]::Ordinal) -or
        $normalized -match '\A[A-Za-z]:' -or
        $normalized.Contains(':')) {
        throw "Package path is absolute, drive-qualified, UNC, or ADS-like: $Path"
    }
    $segments = $normalized.Split([char]'/', [StringSplitOptions]::None)
    if ($segments.Count -eq 0) {
        throw "Package path has no segments: $Path"
    }
    if ($segments.Count -gt 64) {
        throw "Package path exceeds the 64-segment limit: $Path"
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        $pathUtf8Bytes = $strictUtf8.GetByteCount($normalized)
    }
    catch {
        throw "Package path is not valid UTF-8 text: $Path"
    }
    if ($pathUtf8Bytes -gt 1024) {
        throw "Package path exceeds the 1024-byte UTF-8 limit: $Path"
    }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..') {
            throw "Package path contains an empty or traversal segment: $Path"
        }
        if ($segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.EndsWith('.', [StringComparison]::Ordinal)) {
            throw "Package path contains a Windows-ambiguous segment: $Path"
        }
        try {
            $segmentUtf8Bytes = $strictUtf8.GetByteCount($segment)
        }
        catch {
            throw "Package path segment is not valid UTF-8 text: $Path"
        }
        if ($segmentUtf8Bytes -gt 255) {
            throw "Package path segment exceeds the 255-byte UTF-8 limit: $Path"
        }
        if ([regex]::IsMatch(
            $segment,
            '\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\z',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )) {
            throw "Package path contains a reserved Windows device name: $Path"
        }
        if ($segment.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw "Package path contains an invalid Windows filename character: $Path"
        }
    }
    return $segments -join '/'
}

function Assert-EgoPulseUniquePackagePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.HashSet[string]]$ExactPaths,
        [Parameter(Mandatory = $true)][Collections.Generic.Dictionary[string,string]]$CaseInsensitivePaths,
        [Parameter(Mandatory = $true)][string]$Source
    )

    if (-not $ExactPaths.Add($Path)) {
        throw "$Source contains duplicate path: $Path"
    }
    if ($CaseInsensitivePaths.ContainsKey($Path)) {
        $existing = [string]$CaseInsensitivePaths[$Path]
        if ($existing -cne $Path) {
            throw "$Source contains an OrdinalIgnoreCase path collision: $existing and $Path"
        }
    }
    else {
        $CaseInsensitivePaths[$Path] = $Path
    }
}

function New-EgoPulseExclusiveDirectory {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    try {
        [EgoPulseWindowsFileLinkInspector]::CreateDirectoryExclusive($fullPath)
    }
    catch {
        throw "Exclusive directory creation failed: ${fullPath}: $($_.Exception.Message)"
    }
    return Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
}

function Open-EgoPulseExclusiveFile {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    return [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
}

function Copy-EgoPulseFileExclusively {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $input = [IO.File]::Open(
        (Resolve-Path -LiteralPath $SourcePath).Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $output = Open-EgoPulseExclusiveFile -LiteralPath $DestinationPath
        try {
            $input.CopyTo($output)
            $output.Flush($true)
        }
        finally { $output.Dispose() }
    }
    finally { $input.Dispose() }
}

function Write-EgoPulseTextFileExclusively {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][Text.Encoding]$Encoding
    )

    $stream = Open-EgoPulseExclusiveFile -LiteralPath $LiteralPath
    try {
        $writer = [IO.StreamWriter]::new($stream, $Encoding, 1024, $true)
        try {
            $writer.Write($Value)
            $writer.Flush()
            $stream.Flush($true)
        }
        finally { $writer.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Copy-EgoPulsePublicTreeExclusively {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    $source = Get-Item -LiteralPath $SourceRoot -Force -ErrorAction Stop
    if (-not $source.PSIsContainer -or
        ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Public tree source must be an ordinary directory: $SourceRoot"
    }
    $null = New-EgoPulseExclusiveDirectory -LiteralPath $DestinationRoot
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([pscustomobject]@{
        Source = [IO.DirectoryInfo]$source
        Destination = [IO.Path]::GetFullPath($DestinationRoot)
    })
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $current.Source.FullName -Force) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Public tree contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                if ($item.Name -in @('.venv', '__pycache__', '.pytest_cache')) {
                    continue
                }
                $destination = Join-Path $current.Destination $item.Name
                $null = New-EgoPulseExclusiveDirectory -LiteralPath $destination
                $queue.Enqueue([pscustomobject]@{
                    Source = [IO.DirectoryInfo]$item
                    Destination = $destination
                })
                continue
            }
            if (-not ($item -is [IO.FileInfo])) {
                throw "Public tree contains a non-regular item: $($item.FullName)"
            }
            Assert-EgoPulseSingleLinkFile -File $item
            Copy-EgoPulseFileExclusively `
                -SourcePath $item.FullName `
                -DestinationPath (Join-Path $current.Destination $item.Name)
        }
    }
    return $DestinationRoot
}

function Assert-EgoPulseSingleLinkFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileInfo]$File,
        [scriptblock]$LinkCountReader
    )

    try {
        $linkCount = if ($LinkCountReader) {
            & $LinkCountReader $File.FullName
        }
        else {
            [EgoPulseWindowsFileLinkInspector]::GetNumberOfLinks($File.FullName)
        }
    }
    catch {
        throw "Unable to prove package file has exactly one link: $($File.FullName): $($_.Exception.Message)"
    }
    if ($null -eq $linkCount -or [uint64]$linkCount -ne 1) {
        throw "Package file must have exactly one link: $($File.FullName); observed=$linkCount"
    }
}

function Get-EgoPulsePackageFileInventory {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $rootItem = Get-Item -LiteralPath $PackageRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        throw "PackageRoot is not a directory: $PackageRoot"
    }
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "PackageRoot must not be a reparse point: $PackageRoot"
    }
    $root = $rootItem.FullName.TrimEnd('\', '/')
    $rootPrefix = "$root\"
    $directories = [Collections.Generic.Queue[IO.DirectoryInfo]]::new()
    $directories.Enqueue([IO.DirectoryInfo]$rootItem)
    $files = [Collections.Generic.List[object]]::new()
    $exactPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $casePaths = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($directories.Count -gt 0) {
        $directory = $directories.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory.FullName -Force) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Package tree contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                $directories.Enqueue([IO.DirectoryInfo]$item)
                continue
            }
            if (-not ($item -is [IO.FileInfo])) {
                throw "Package tree contains a non-regular item: $($item.FullName)"
            }
            Assert-EgoPulseSingleLinkFile -File $item
            $fullPath = [IO.Path]::GetFullPath($item.FullName)
            if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Package file escapes PackageRoot: $fullPath"
            }
            $relative = ConvertTo-EgoPulsePackagePath -Path $fullPath.Substring($rootPrefix.Length)
            Assert-EgoPulseUniquePackagePath -Path $relative -ExactPaths $exactPaths -CaseInsensitivePaths $casePaths -Source 'PackageRoot'
            $files.Add([pscustomobject]@{
                Path = $relative
                FullPath = $fullPath
                Length = [int64]$item.Length
            })
        }
    }
    return @($files | Sort-Object Path)
}

function New-EgoPulsePackageArchiveExclusively {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )

    $root = (Resolve-Path -LiteralPath $PackageRoot).Path.TrimEnd('\', '/')
    $topLevel = ConvertTo-EgoPulsePackagePath -Path (Split-Path -Leaf $root)
    $inventory = @(Get-EgoPulsePackageFileInventory -PackageRoot $root)
    $stream = Open-EgoPulseExclusiveFile -LiteralPath $ArchivePath
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $null = $archive.CreateEntry("$topLevel/")
            foreach ($file in $inventory) {
                $entry = $archive.CreateEntry(
                    "$topLevel/$($file.Path)",
                    [IO.Compression.CompressionLevel]::Optimal
                )
                $input = [IO.File]::Open(
                    $file.FullPath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    [IO.FileShare]::Read
                )
                try {
                    $output = $entry.Open()
                    try { $input.CopyTo($output) } finally { $output.Dispose() }
                }
                finally { $input.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return $ArchivePath
}

function Test-EgoPulsePackageManifest {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [string[]]$RequiredFiles = @('config/agentos-config.example.json')
    )

    $inventory = @(Get-EgoPulsePackageFileInventory -PackageRoot $PackageRoot)
    $root = (Get-Item -LiteralPath $PackageRoot -Force).FullName
    $manifestPath = Join-Path $root 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Required package file is missing: SHA256SUMS'
    }
    $lines = @(Get-Content -LiteralPath $manifestPath)
    if ($lines.Count -eq 0) {
        throw 'SHA256SUMS is empty.'
    }
    $manifestEntries = [Collections.Generic.List[object]]::new()
    $exactPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $casePaths = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $lines) {
        if ($line -notmatch '\A([0-9A-Fa-f]{64})  (\S.*)\z') {
            throw "Malformed SHA256SUMS line: $line"
        }
        $relative = ConvertTo-EgoPulsePackagePath -Path $Matches[2]
        if ($relative.Equals('SHA256SUMS', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'SHA256SUMS must not list itself.'
        }
        Assert-EgoPulseUniquePackagePath -Path $relative -ExactPaths $exactPaths -CaseInsensitivePaths $casePaths -Source 'SHA256SUMS'
        $manifestEntries.Add([pscustomobject]@{
            Path = $relative
            Digest = $Matches[1].ToLowerInvariant()
        })
    }

    $packagePaths = @($inventory | Where-Object { $_.Path -cne 'SHA256SUMS' } | ForEach-Object { $_.Path })
    $manifestPaths = @($manifestEntries | ForEach-Object { $_.Path })
    $missing = @($packagePaths | Where-Object { -not $exactPaths.Contains($_) })
    $packageSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($path in $packagePaths) { $null = $packageSet.Add($path) }
    $extra = @($manifestPaths | Where-Object { -not $packageSet.Contains($_) })
    if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
        throw "SHA256SUMS path set is not closed; missing=$($missing -join ',') extra=$($extra -join ',')"
    }
    foreach ($required in $RequiredFiles) {
        $safeRequired = ConvertTo-EgoPulsePackagePath -Path $required
        if (-not $packageSet.Contains($safeRequired)) {
            throw "Required package file is missing: $safeRequired"
        }
    }

    $inventoryByPath = @{}
    foreach ($file in $inventory) { $inventoryByPath[$file.Path] = $file }
    foreach ($entry in $manifestEntries) {
        $actual = Get-EgoPulseSha256Hex -LiteralPath $inventoryByPath[$entry.Path].FullPath
        if ($actual -cne $entry.Digest) {
            throw "SHA-256 mismatch for $($entry.Path): expected $($entry.Digest), got $actual"
        }
    }
    return [pscustomobject]@{
        Root = $root
        Inventory = $inventory
        Entries = @($manifestEntries)
    }
}

function Assert-EgoPulseArchiveArguments {
    param([string]$ArchivePath, [string]$ExpectedArchiveSha256)

    $hasArchive = -not [string]::IsNullOrWhiteSpace($ArchivePath)
    $hasExpected = -not [string]::IsNullOrWhiteSpace($ExpectedArchiveSha256)
    if ($hasArchive -ne $hasExpected) {
        throw 'ArchivePath and ExpectedArchiveSha256 must be provided together.'
    }
    if ($hasExpected -and $ExpectedArchiveSha256 -notmatch '\A[0-9A-Fa-f]{64}\z') {
        throw 'ExpectedArchiveSha256 must be exactly 64 hexadecimal characters.'
    }
    return $hasArchive
}

function Test-EgoPulseZipEntryKind {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )

    $attributes = [BitConverter]::ToUInt32(
        [BitConverter]::GetBytes([int32]$Entry.ExternalAttributes),
        0
    )
    $unixKind = ($attributes -shr 16) -band 0xf000
    $dosAttributes = $attributes -band 0xffff
    if (($dosAttributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "ZIP entry is marked as a reparse point: $($Entry.FullName)"
    }
    if ($unixKind -ne 0) {
        $expectedKind = if ($IsDirectory) { 0x4000 } else { 0x8000 }
        if ($unixKind -ne $expectedKind) {
            throw "ZIP entry is not a regular file or directory: $($Entry.FullName)"
        }
    }
}

function Get-EgoPulseArchiveTopLevel {
    param([Parameter(Mandatory = $true)][string]$ExpectedTopLevel)

    $safeTopLevel = ConvertTo-EgoPulsePackagePath -Path $ExpectedTopLevel
    if ($safeTopLevel.Contains('/')) {
        throw 'Expected ZIP top level must be one path segment.'
    }
    return $safeTopLevel
}

function Get-EgoPulseStreamSha256Hex {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if (-not $Stream.CanSeek) {
        throw 'Archive verification requires a seekable stream.'
    }
    $Stream.Position = 0
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($sha256.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
    $Stream.Position = 0
    return $digest
}

function Add-EgoPulseZipPathTreeEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$IsDirectory,
        [Parameter(Mandatory = $true)][Collections.Generic.Dictionary[string,object]]$PathTree
    )

    $segments = $Path.Split([char]'/')
    $nodePath = ''
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $nodePath = if ($index -eq 0) {
            $segments[$index]
        }
        else {
            "$nodePath/$($segments[$index])"
        }
        $isLeaf = $index -eq ($segments.Count - 1)
        $requiredKind = if ($isLeaf -and -not $IsDirectory) { 'file' } else { 'directory' }
        if ($PathTree.ContainsKey($nodePath)) {
            $existing = $PathTree[$nodePath]
            if ([string]$existing.Path -cne $nodePath) {
                throw "ZIP contains an OrdinalIgnoreCase ancestor collision: $($existing.Path) and $nodePath"
            }
            if ([string]$existing.Kind -cne $requiredKind) {
                throw "ZIP path tree has a file/directory conflict: $nodePath"
            }
            if ($isLeaf) {
                $existing.Explicit = $true
            }
            continue
        }
        $PathTree[$nodePath] = [pscustomobject]@{
            Path = $nodePath
            Kind = $requiredKind
            Explicit = $isLeaf
        }
    }
}

function Test-EgoPulseZipArchiveEntries {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$ExpectedTopLevel,
        [int]$MaximumEntryCount = 20000,
        [int64]$MaximumSingleExpandedBytes = 536870912,
        [int64]$MaximumTotalExpandedBytes = 2147483648,
        [double]$MaximumCompressionRatio = 200.0
    )

    $safeTopLevel = Get-EgoPulseArchiveTopLevel -ExpectedTopLevel $ExpectedTopLevel
    if ($Archive.Entries.Count -eq 0 -or $Archive.Entries.Count -gt $MaximumEntryCount) {
        throw "ZIP entry count is outside the allowed range: $($Archive.Entries.Count)"
    }
    $exactPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $casePaths = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pathTree = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $totalExpanded = [int64]0
    foreach ($entry in $Archive.Entries) {
        $isDirectory = $entry.FullName.EndsWith('/', [StringComparison]::Ordinal) -or
            $entry.FullName.EndsWith('\', [StringComparison]::Ordinal)
        $relative = ConvertTo-EgoPulsePackagePath -Path $entry.FullName -AllowDirectorySuffix:$isDirectory
        Add-EgoPulseZipPathTreeEntry -Path $relative -IsDirectory $isDirectory -PathTree $pathTree
        Assert-EgoPulseUniquePackagePath -Path $relative -ExactPaths $exactPaths -CaseInsensitivePaths $casePaths -Source 'ZIP'
        $segments = $relative.Split([char]'/')
        if ($segments[0] -cne $safeTopLevel) {
            throw "ZIP must contain one exact top-level directory named ${safeTopLevel}: $relative"
        }
        if ($segments.Count -eq 1 -and -not $isDirectory) {
            throw "ZIP top-level entry must be a directory: $relative"
        }
        Test-EgoPulseZipEntryKind -Entry $entry -IsDirectory $isDirectory
        if ($isDirectory) {
            if ($entry.Length -ne 0) {
                throw "ZIP directory entry has content: $relative"
            }
            continue
        }
        if ($entry.Length -gt $MaximumSingleExpandedBytes) {
            throw "ZIP entry exceeds the single-file expansion limit: $relative"
        }
        if ($entry.Length -gt ([int64]::MaxValue - $totalExpanded)) {
            throw 'ZIP expanded-size total overflowed.'
        }
        $totalExpanded += $entry.Length
        if ($totalExpanded -gt $MaximumTotalExpandedBytes) {
            throw 'ZIP exceeds the total expansion limit.'
        }
        $compressed = [Math]::Max([int64]1, [int64]$entry.CompressedLength)
        $ratio = [double]$entry.Length / [double]$compressed
        if ($ratio -gt $MaximumCompressionRatio) {
            throw "ZIP entry exceeds the compression-ratio limit: $relative"
        }
    }
    return [pscustomobject]@{
        TopLevel = $safeTopLevel
        EntryCount = $exactPaths.Count
        TotalExpandedBytes = $totalExpanded
    }
}

function Test-EgoPulseArchiveEnvelope {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedTopLevel,
        [int]$MaximumEntryCount = 20000,
        [int64]$MaximumSingleExpandedBytes = 536870912,
        [int64]$MaximumTotalExpandedBytes = 2147483648,
        [double]$MaximumCompressionRatio = 200.0
    )

    $null = Assert-EgoPulseArchiveArguments -ArchivePath $ArchivePath -ExpectedArchiveSha256 $ExpectedArchiveSha256
    $resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath).Path
    $stream = [IO.File]::Open($resolvedArchive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $actualArchiveSha256 = Get-EgoPulseStreamSha256Hex -Stream $stream
        if ($actualArchiveSha256 -cne $ExpectedArchiveSha256.ToLowerInvariant()) {
            throw "Archive SHA-256 mismatch: expected $ExpectedArchiveSha256, got $actualArchiveSha256"
        }
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            $preflight = Test-EgoPulseZipArchiveEntries `
                -Archive $archive `
                -ExpectedTopLevel $ExpectedTopLevel `
                -MaximumEntryCount $MaximumEntryCount `
                -MaximumSingleExpandedBytes $MaximumSingleExpandedBytes `
                -MaximumTotalExpandedBytes $MaximumTotalExpandedBytes `
                -MaximumCompressionRatio $MaximumCompressionRatio
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return [pscustomobject]@{
        ArchivePath = $resolvedArchive
        ArchiveSha256 = $actualArchiveSha256
        TopLevel = $preflight.TopLevel
        EntryCount = $preflight.EntryCount
        TotalExpandedBytes = $preflight.TotalExpandedBytes
    }
}

function Expand-EgoPulseArchiveSafely {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedTopLevel,
        [int]$MaximumEntryCount = 20000,
        [int64]$MaximumSingleExpandedBytes = 536870912,
        [int64]$MaximumTotalExpandedBytes = 2147483648,
        [double]$MaximumCompressionRatio = 200.0
    )

    $null = Assert-EgoPulseArchiveArguments -ArchivePath $ArchivePath -ExpectedArchiveSha256 $ExpectedArchiveSha256
    $resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath).Path
    $temporaryRoot = $null
    $stream = [IO.File]::Open($resolvedArchive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $actualArchiveSha256 = Get-EgoPulseStreamSha256Hex -Stream $stream
        if ($actualArchiveSha256 -cne $ExpectedArchiveSha256.ToLowerInvariant()) {
            throw "Archive SHA-256 mismatch: expected $ExpectedArchiveSha256, got $actualArchiveSha256"
        }
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            $preflight = Test-EgoPulseZipArchiveEntries `
                -Archive $archive `
                -ExpectedTopLevel $ExpectedTopLevel `
                -MaximumEntryCount $MaximumEntryCount `
                -MaximumSingleExpandedBytes $MaximumSingleExpandedBytes `
                -MaximumTotalExpandedBytes $MaximumTotalExpandedBytes `
                -MaximumCompressionRatio $MaximumCompressionRatio
            $temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
            $temporaryRoot = Join-Path $temporaryBase "egopulse-package-verify-$([Guid]::NewGuid().ToString('N'))"
            if (Test-Path -LiteralPath $temporaryRoot) {
                throw "Temporary extraction root already exists: $temporaryRoot"
            }
            $null = New-Item -ItemType Directory -Path $temporaryRoot
            $rootPrefix = "$([IO.Path]::GetFullPath($temporaryRoot).TrimEnd('\', '/'))\"
            foreach ($entry in $archive.Entries) {
                $isDirectory = $entry.FullName.EndsWith('/', [StringComparison]::Ordinal) -or
                    $entry.FullName.EndsWith('\', [StringComparison]::Ordinal)
                $relative = ConvertTo-EgoPulsePackagePath -Path $entry.FullName -AllowDirectorySuffix:$isDirectory
                $destination = [IO.Path]::GetFullPath((Join-Path $temporaryRoot $relative.Replace('/', '\')))
                if (-not $destination.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "ZIP extraction target escapes the temporary root: $relative"
                }
                if ($isDirectory) {
                    if (-not (Test-Path -LiteralPath $destination)) {
                        $null = New-Item -ItemType Directory -Path $destination
                    }
                    continue
                }
                $parent = Split-Path -Parent $destination
                if (-not (Test-Path -LiteralPath $parent)) {
                    $null = New-Item -ItemType Directory -Force -Path $parent
                }
                if (Test-Path -LiteralPath $destination) {
                    throw "ZIP extraction refuses to overwrite an existing path: $relative"
                }
                $input = $entry.Open()
                try {
                    $output = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    try { $input.CopyTo($output) } finally { $output.Dispose() }
                }
                finally {
                    $input.Dispose()
                }
            }
        }
        finally { $archive.Dispose() }
        return [pscustomobject]@{
            TemporaryRoot = $temporaryRoot
            PackageRoot = Join-Path $temporaryRoot $preflight.TopLevel
            ArchiveSha256 = $actualArchiveSha256
        }
    }
    catch {
        if ($temporaryRoot) {
            Remove-EgoPulseVerificationTemporaryRoot -TemporaryRoot $temporaryRoot
        }
        throw
    }
    finally { $stream.Dispose() }
}

function Remove-EgoPulseVerificationTemporaryRoot {
    param([Parameter(Mandatory = $true)][string]$TemporaryRoot)

    if (-not (Test-Path -LiteralPath $TemporaryRoot)) {
        return
    }
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $TemporaryRoot).Path).TrimEnd('\', '/')
    $temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
    $expectedPrefix = "$temporaryBase\egopulse-package-verify-"
    $leaf = Split-Path -Leaf $resolved
    if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch '\Aegopulse-package-verify-[0-9a-f]{32}\z') {
        throw "Refusing to remove an unverified package temporary root: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Compare-EgoPulsePackageTrees {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$ExtractedRoot
    )

    $sourceManifest = Test-EgoPulsePackageManifest -PackageRoot $SourceRoot
    $extractedManifest = Test-EgoPulsePackageManifest -PackageRoot $ExtractedRoot
    $sourceFiles = @($sourceManifest.Inventory)
    $extractedFiles = @($extractedManifest.Inventory)
    if ($sourceFiles.Count -ne $extractedFiles.Count) {
        throw 'Source and extracted package file counts differ.'
    }
    $extractedByPath = @{}
    foreach ($file in $extractedFiles) { $extractedByPath[$file.Path] = $file }
    foreach ($source in $sourceFiles) {
        if (-not $extractedByPath.ContainsKey($source.Path)) {
            throw "Extracted package is missing source file: $($source.Path)"
        }
        $sourceHash = Get-EgoPulseSha256Hex -LiteralPath $source.FullPath
        $extractedHash = Get-EgoPulseSha256Hex -LiteralPath $extractedByPath[$source.Path].FullPath
        if ($sourceHash -cne $extractedHash) {
            throw "Source and extracted package differ: $($source.Path)"
        }
    }
}

function Invoke-EgoPulseRestoredEnvironment {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)

    $pythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
    $userConfig = [Environment]::GetEnvironmentVariable('EGOPULSE_USER_CONFIG', 'Process')
    try {
        & $Action
    }
    finally {
        [Environment]::SetEnvironmentVariable('PYTHONPATH', $pythonPath, 'Process')
        [Environment]::SetEnvironmentVariable('EGOPULSE_USER_CONFIG', $userConfig, 'Process')
    }
}
