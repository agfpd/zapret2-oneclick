[CmdletBinding()]
param(
    [string]$Root,
    [string]$BaselinePath
)

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
$rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
if (-not $BaselinePath) { $BaselinePath = Join-Path $rootFull 'compliance\public-text-baseline.json' }
if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
    throw "Public-text baseline is missing: $BaselinePath"
}

$utf8Strict = New-Object Text.UTF8Encoding($false, $true)
$baseline = [IO.File]::ReadAllText($BaselinePath, $utf8Strict) | ConvertFrom-Json
if ($baseline.schemaVersion -ne 1) { throw 'Unsupported public-text baseline schema.' }
if ($baseline.baselineCommit -ne 'fef77e99e00e6eb1bd0ab43c9af4aa7c6dad4f97') {
    throw 'Public-text baseline must remain bound to exact published v1.0.5.'
}
if (-not $baseline.patterns -or -not $baseline.surface.requiredPaths) {
    throw 'Public-text baseline is incomplete.'
}

function Get-PublicTextRelativePath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Public-text path escapes Root: $Path"
    }
    return $full.Substring($rootFull.Length + 1).Replace('\', '/')
}

function Get-LineSha256([string]$Line) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Line)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha.Dispose() }
}

$surface = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
$rootExtensions = @($baseline.surface.rootExtensions | ForEach-Object { ([string]$_).ToLowerInvariant() })
Get-ChildItem -LiteralPath $rootFull -File | Where-Object {
    $rootExtensions -contains $_.Extension.ToLowerInvariant()
} | ForEach-Object {
    $surface[(Get-PublicTextRelativePath -Path $_.FullName)] = $_.FullName
}
foreach ($directory in @($baseline.surface.recursiveDirectories)) {
    $directoryPath = Join-Path $rootFull ([string]$directory)
    if (-not (Test-Path -LiteralPath $directoryPath -PathType Container)) {
        throw "Required public-text directory is missing: $directory"
    }
    Get-ChildItem -LiteralPath $directoryPath -Recurse -File | Where-Object {
        $rootExtensions -contains $_.Extension.ToLowerInvariant()
    } | ForEach-Object {
        $surface[(Get-PublicTextRelativePath -Path $_.FullName)] = $_.FullName
    }
}
foreach ($required in @($baseline.surface.requiredPaths)) {
    if (-not $surface.ContainsKey(([string]$required).Replace('\', '/'))) {
        throw "Required public-text file is outside the scanned surface or missing: $required"
    }
}

$patterns = @{}
foreach ($entry in @($baseline.patterns)) {
    $id = [string]$entry.id
    if (-not $id -or $patterns.ContainsKey($id)) { throw "Duplicate or empty public-text pattern id: $id" }
    $patterns[$id] = [Text.RegularExpressions.Regex]::new(
        ([string]$entry.regex),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

# Every current service group must bind to a target-name pattern. A catalog
# addition therefore fails closed until the public gate is deliberately extended.
$catalogPath = Join-Path $rootFull 'config\services.json'
$catalog = [IO.File]::ReadAllText($catalogPath, $utf8Strict) | ConvertFrom-Json
$bindings = @{}
foreach ($binding in @($baseline.catalogBindings)) {
    $groupId = [string]$binding.groupId
    $patternId = [string]$binding.patternId
    if ($bindings.ContainsKey($groupId) -or -not $patterns.ContainsKey($patternId)) {
        throw "Invalid public-text catalog binding: $groupId -> $patternId"
    }
    $bindings[$groupId] = $patternId
}
foreach ($group in @($catalog.groups)) {
    $groupId = [string]$group.id
    if (-not $bindings.ContainsKey($groupId)) {
        throw "Public-text gate has no target-name binding for catalog group: $groupId"
    }
    $catalogIdentity = @($group.id, $group.displayName, @($group.probeDomains)) -join ' '
    if (-not $patterns[$bindings[$groupId]].IsMatch($catalogIdentity)) {
        throw "Target-name pattern does not match its catalog group: $groupId"
    }
}
foreach ($groupId in @($bindings.Keys)) {
    if (-not @($catalog.groups | Where-Object { [string]$_.id -eq $groupId })) {
        throw "Public-text baseline has a stale catalog binding: $groupId"
    }
}

$allowances = @{}
foreach ($allowed in @($baseline.allowedOccurrences)) {
    $path = ([string]$allowed.path).Replace('\', '/')
    $patternId = [string]$allowed.patternId
    $lineHash = ([string]$allowed.lineSha256).ToLowerInvariant()
    $count = [int]$allowed.count
    if (-not $surface.ContainsKey($path) -or -not $patterns.ContainsKey($patternId) -or
        $lineHash -notmatch '^[0-9a-f]{64}$' -or $count -lt 1) {
        throw "Invalid public-text baseline allowance: $path / $patternId"
    }
    if ($patternId -ne 'purpose-vpn') {
        throw "Only the exact published v1.0.5 VPN safety lines may be baseline-allowed: $patternId"
    }
    $key = "$path|$patternId|$lineHash"
    if ($allowances.ContainsKey($key)) { throw "Duplicate public-text baseline allowance: $key" }
    $allowances[$key] = $count
}

$violations = New-Object Collections.Generic.List[string]
foreach ($path in @($surface.Keys | Sort-Object)) {
    $lines = [IO.File]::ReadAllLines($surface[$path], $utf8Strict)
    for ($lineIndex = 0; $lineIndex -lt $lines.Length; $lineIndex++) {
        $line = $lines[$lineIndex]
        foreach ($patternId in @($patterns.Keys | Sort-Object)) {
            $matches = $patterns[$patternId].Matches($line).Count
            if ($matches -eq 0) { continue }
            $key = "$path|$patternId|$(Get-LineSha256 -Line $line)"
            $remaining = if ($allowances.ContainsKey($key)) { [int]$allowances[$key] } else { 0 }
            if ($remaining -lt $matches) {
                $violations.Add("$path`:$($lineIndex + 1): forbidden public-text pattern '$patternId' ($matches occurrence(s), $remaining baseline allowance(s))")
            }
            else { $allowances[$key] = $remaining - $matches }
        }
    }
}
if ($violations.Count -gt 0) {
    throw ("Release blocked by public-text neutrality gate:`n" + ($violations -join "`n"))
}

Write-Host "Public-text neutrality gate passed ($($surface.Count) files; baseline $($baseline.baselineCommit))." -ForegroundColor Green
