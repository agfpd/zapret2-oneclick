[CmdletBinding()]
param(
    [string]$Root,
    [string]$ReleaseVersion = '1.0.0',
    [string]$OutputDirectory,
    [switch]$SkipSourceArtifact,
    [string]$SourceCache
)

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $Root 'artifacts' }
$stageRoot = Join-Path $env:TEMP ('z2o-release-' + [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $stageRoot 'zapret2-oneclick'
$binaryZip = Join-Path $OutputDirectory "zapret2-oneclick-v$ReleaseVersion.zip"
$sourceZip = Join-Path $OutputDirectory "zapret2-oneclick-v$ReleaseVersion-sources.zip"
$checksums = Join-Path $OutputDirectory "zapret2-oneclick-v$ReleaseVersion-SHA256SUMS.txt"

try {
    & (Join-Path $Root 'build\check-release-readiness.ps1') -Root $Root
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($name in @(
        'setup.cmd', 'uninstall.cmd', 'START-HERE.txt', 'README.md',
        'THIRD_PARTY_NOTICES.md', 'vendor', 'config', 'launcher', 'checksums',
        'patches', 'compliance'
    )) {
        Copy-Item -LiteralPath (Join-Path $Root $name) -Destination $stage -Recurse -Force
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Remove-Item -LiteralPath $binaryZip -Force -ErrorAction SilentlyContinue
    Compress-Archive -LiteralPath $stage -DestinationPath $binaryZip -CompressionLevel Optimal

    $artifacts = @($binaryZip)
    if (-not $SkipSourceArtifact) {
        & (Join-Path $Root 'build\Build-SourceArtifact.ps1') -Root $Root -Output $sourceZip -SourceCache $SourceCache
        $artifacts += $sourceZip
    }

    $lines = foreach ($artifact in $artifacts) {
        '{0} *{1}' -f (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant(), [IO.Path]::GetFileName($artifact)
    }
    # Use LF explicitly so the conventional checksum file works with both
    # Windows tooling and sha256sum/shasum on Unix hosts.
    [IO.File]::WriteAllText($checksums, (($lines -join "`n") + "`n"), [Text.Encoding]::ASCII)
    Write-Host "Release artifact: $binaryZip" -ForegroundColor Green
    if (-not $SkipSourceArtifact) { Write-Host "Source artifact:  $sourceZip" -ForegroundColor Green }
    Write-Host "Checksums:       $checksums" -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
}
