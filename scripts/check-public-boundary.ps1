param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Path and suffix rules. These can only see a file's name, never what it carries,
# which is how local machine paths and private governance references reached a
# public repository in the first place. The content rules below close that gap.
$forbiddenRoots = @(
    '.agents/',
    '.codex/',
    'ai-os-research/',
    'founder-agent-os/',
    'governance/',
    'methodology/',
    'planning/',
    'research/',
    'specs/'
)
$forbiddenSecretSuffixes = @(
    '.env',
    '.key',
    '.p12',
    '.pem',
    '.pfx'
)

$visibleFiles = @(& git ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to enumerate visible repository files'
}

$violations = [System.Collections.Generic.List[string]]::new()
foreach ($path in $visibleFiles) {
    $normalized = $path.Replace('\', '/').ToLowerInvariant()
    foreach ($root in $forbiddenRoots) {
        if ($normalized.StartsWith($root)) {
            $violations.Add("$path`: private governance or agent-runtime root is forbidden")
        }
    }
    foreach ($suffix in $forbiddenSecretSuffixes) {
        if ($normalized.EndsWith($suffix)) {
            $violations.Add("$path`: credential-bearing file type is forbidden")
        }
    }
}

# ---------------------------------------------------------------------------
# Content rules (E-104)
# ---------------------------------------------------------------------------
#
# Two of these rules ship with a grandfather allowance instead of a clean slate,
# because the remaining hits are frozen contract content: contracts/manifest.json
# and the IMPLEMENTATION-SSOT baselines carry digests over the very text, so
# removing a reference is a contract change with its own review. Until that
# lands the rule blocks any *increase*, which is what stops the leak growing
# while the change is pending. See scripts/public-boundary-allowlist.json.
#
# The rest block outright and currently match nothing.

$allowlistPath = Join-Path $PSScriptRoot 'public-boundary-allowlist.json'
if (-not (Test-Path -LiteralPath $allowlistPath)) {
    throw "Missing public-boundary allowlist: $allowlistPath"
}
$allowlist = Get-Content -LiteralPath $allowlistPath -Raw | ConvertFrom-Json

$governanceAllowance = @{}
foreach ($entry in $allowlist.governanceRefCounts) {
    $governanceAllowance[$entry.path.Replace('\', '/')] = [int]$entry.count
}

$textExtensions = @(
    '.md', '.txt', '.rs', '.toml', '.json', '.jsonl', '.yml', '.yaml',
    '.ts', '.tsx', '.js', '.mjs', '.ps1', '.sh', '.proto', '.csv', '.css'
)

# B1: a real user profile path. Synthetic names are fixtures, not a machine.
$userProfilePattern = 'C:\\Users\\([A-Za-z0-9._-]+)'
$syntheticUserNames = @('founder', 'test')
# B2: a reference into private governance conversation records.
$governanceRefPattern = 'conversation:20\d\d-\d\d-\d\d'
# B3/B4/B5: must be absent from a public repository.
$privateAddressPattern = '(?<![\d.])(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+)(?![\d.])'
$privateProjectPattern = 'p1core|skynet|sego-handoff|egopulse-handoff'
$credentialLiteralPattern = '(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*"[A-Za-z0-9_\-]{24,}"'

$contentScanCount = 0
# This file necessarily contains the literals it forbids, so scanning it would
# report the rule as its own violation. Excluding one small, reviewed rule file
# is the honest option; hiding the literals in fragments would make the rules
# harder to read without making them harder to bypass.
$selfRelativePath = 'scripts/check-public-boundary.ps1'
foreach ($path in $visibleFiles) {
    $extension = [IO.Path]::GetExtension($path).ToLowerInvariant()
    if ($textExtensions -notcontains $extension) { continue }
    if (-not (Test-Path -LiteralPath $path)) { continue }

    $normalized = $path.Replace('\', '/')
    if ($normalized -eq $selfRelativePath) { continue }
    $content = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $path).Path)
    $contentScanCount++

    # B1
    foreach ($match in [regex]::Matches($content, $userProfilePattern)) {
        $name = $match.Groups[1].Value
        if ($syntheticUserNames -notcontains $name) {
            $violations.Add("$normalized`: B1 local user-profile path names a real account ($name)")
        }
    }

    # B2
    $governanceCount = ([regex]::Matches($content, $governanceRefPattern)).Count
    if ($governanceCount -gt 0) {
        $allowed = if ($governanceAllowance.ContainsKey($normalized)) { $governanceAllowance[$normalized] } else { 0 }
        if ($governanceCount -gt $allowed) {
            $violations.Add("$normalized`: B2 private governance references rose to $governanceCount (allowed $allowed); add one only with a contract change, not an allowlist edit")
        }
    }

    # B3
    if ([regex]::IsMatch($content, $privateAddressPattern)) {
        $violations.Add("$normalized`: B3 private network address")
    }

    # B4
    if ([regex]::IsMatch($content, $privateProjectPattern)) {
        $violations.Add("$normalized`: B4 private project or handoff directory name")
    }

    # B5
    if ([regex]::IsMatch($content, $credentialLiteralPattern)) {
        $violations.Add("$normalized`: B5 credential-shaped literal")
    }
}

if ($violations.Count -gt 0) {
    throw "Public product-repository boundary failed:`n$($violations -join "`n")"
}

Write-Output "public_repository_boundary=passed visible_files=$($visibleFiles.Count) content_scanned=$contentScanCount"
