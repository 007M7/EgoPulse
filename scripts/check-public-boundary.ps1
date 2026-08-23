param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

if ($violations.Count -gt 0) {
    throw "Public product-repository boundary failed:`n$($violations -join "`n")"
}

Write-Output "public_repository_boundary=passed visible_files=$($visibleFiles.Count)"
