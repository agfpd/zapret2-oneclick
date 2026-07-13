[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$Output = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\zapret2-oneclick-sources.zip'),
    [string]$SourceCache
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$lockPath = Join-Path $Root 'compliance\cygwin-packages.lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($lock.status -ne 'complete' -or $lock.packages.Count -eq 0) { throw 'Cygwin source lock is incomplete.' }

$work = Join-Path $env:TEMP ("z2o-sources-" + [Guid]::NewGuid().ToString('N'))
$payload = Join-Path $work 'zapret2-oneclick-sources'
$archives = Join-Path $payload 'cygwin-source-archives'
New-Item -ItemType Directory -Force -Path $archives | Out-Null
try {
    function Get-SourceFile([string]$Url, [string]$Destination) {
        $name = [IO.Path]::GetFileName(([Uri]$Url).AbsolutePath)
        $cached = $null
        if ($SourceCache) {
            $cached = Get-ChildItem -LiteralPath $SourceCache -Recurse -File -Filter $name -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if ($cached) { Copy-Item -LiteralPath $cached.FullName -Destination $Destination }
        else { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination }
    }

    $seen = @{}
    foreach ($pkg in $lock.packages) {
        $source = $pkg.source
        if ($seen.ContainsKey($source.path)) { continue }
        $seen[$source.path] = $true
        $url = $lock.setup.mirror.TrimEnd('/') + '/' + $source.path
        $file = Join-Path $archives ([IO.Path]::GetFileName($source.path))
        Get-SourceFile -Url $url -Destination $file
        $actual = (Get-FileHash -Algorithm SHA512 -LiteralPath $file).Hash.ToLowerInvariant()
        if ($actual -ne $source.sha512) { throw "SHA-512 mismatch for $url" }
    }
    foreach ($source in $lock.customSources) {
        $file = Join-Path $archives ([IO.Path]::GetFileName(([Uri]$source.url).AbsolutePath))
        Get-SourceFile -Url $source.url -Destination $file
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        if ($actual -ne $source.sha256) { throw "SHA-256 mismatch for $($source.url)" }
    }

    $upstream = Join-Path $payload 'upstream'
    New-Item -ItemType Directory -Force -Path $upstream | Out-Null
    $zapretUrl = 'https://github.com/bol-van/zapret2/releases/download/v1.0.2/zapret2-v1.0.2.zip'
    $zapretArchive = Join-Path $upstream 'zapret2-v1.0.2.zip'
    Get-SourceFile -Url $zapretUrl -Destination $zapretArchive
    $zapretHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zapretArchive).Hash.ToLowerInvariant()
    if ($zapretHash -ne '45f90e1c70db104a735cd0f99e5644cea84689bf05dadb498953f334999b1ebb') {
        throw 'zapret2 v1.0.2 source archive SHA-256 mismatch.'
    }

    Copy-Item -LiteralPath $lockPath -Destination $payload
    Copy-Item -LiteralPath (Join-Path $Root 'patches') -Destination $payload -Recurse
    Copy-Item -LiteralPath (Join-Path $Root 'build') -Destination $payload -Recurse
    Copy-Item -LiteralPath (Join-Path $Root 'THIRD_PARTY_NOTICES.md') -Destination $payload
    if (Test-Path -LiteralPath $Output) { Remove-Item -LiteralPath $Output -Force }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null
    Compress-Archive -LiteralPath $payload -DestinationPath $Output -CompressionLevel Optimal
    Write-Host "Corresponding-source artifact: $Output"
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
