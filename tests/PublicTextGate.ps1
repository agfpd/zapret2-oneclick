$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$gate = Join-Path $root 'build\Test-PublicTextNeutrality.ps1'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Copy-PublicTextFixture([string]$Destination) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($directory in @('patches', 'compliance', 'config')) {
        New-Item -ItemType Directory -Path (Join-Path $Destination $directory) -Force | Out-Null
    }
    foreach ($path in @('README.md', 'START-HERE.txt', 'THIRD_PARTY_NOTICES.md')) {
        Copy-Item -LiteralPath (Join-Path $root $path) -Destination (Join-Path $Destination $path)
    }
    Copy-Item -LiteralPath (Join-Path $root 'patches\README.md') -Destination (Join-Path $Destination 'patches\README.md')
    Copy-Item -LiteralPath (Join-Path $root 'compliance\README.md') -Destination (Join-Path $Destination 'compliance\README.md')
    Copy-Item -LiteralPath (Join-Path $root 'compliance\public-text-baseline.json') -Destination (Join-Path $Destination 'compliance\public-text-baseline.json')
    Copy-Item -LiteralPath (Join-Path $root 'config\services.json') -Destination (Join-Path $Destination 'config\services.json')
}

$temp = Join-Path $env:TEMP ('z2o-public-text-' + [Guid]::NewGuid().ToString('N'))
try {
    $positive = Join-Path $temp 'positive'
    Copy-PublicTextFixture -Destination $positive
    Add-Content -LiteralPath (Join-Path $positive 'README.md') -Value 'The additional group does not affect the required result.' -Encoding UTF8
    & $gate -Root $positive
    Write-Host 'Positive neutral change and unchanged v1.0.5 VPN baseline passed.' -ForegroundColor Green

    $forbidden = Join-Path $temp 'forbidden-target'
    Copy-PublicTextFixture -Destination $forbidden
    Add-Content -LiteralPath (Join-Path $forbidden 'README.md') -Value 'YouTube is checked separately.' -Encoding UTF8
    $forbiddenFailed = $false
    try { & $gate -Root $forbidden }
    catch { $forbiddenFailed = $_.Exception.Message -match "target-youtube" }
    Assert-True $forbiddenFailed 'a newly added target-service token must block release readiness'
    Write-Host 'Negative target-service token injection was blocked.' -ForegroundColor Green

    $baselineDrift = Join-Path $temp 'baseline-drift'
    Copy-PublicTextFixture -Destination $baselineDrift
    $readme = Join-Path $baselineDrift 'README.md'
    $lines = [Collections.Generic.List[string]]::new([IO.File]::ReadAllLines($readme, [Text.Encoding]::UTF8))
    $vpnLine = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)(?<![A-Z0-9_])VPN(?![A-Z0-9_])') { $vpnLine = $i; break }
    }
    Assert-True ($vpnLine -ge 0) 'fixture must retain the published VPN safety baseline'
    $lines[$vpnLine] = $lines[$vpnLine] + ' changed'
    [IO.File]::WriteAllLines($readme, $lines, (New-Object Text.UTF8Encoding($false)))
    $driftFailed = $false
    try { & $gate -Root $baselineDrift }
    catch { $driftFailed = $_.Exception.Message -match 'purpose-vpn' }
    Assert-True $driftFailed 'a changed forbidden-token line must not inherit the published baseline allowance'
    Write-Host 'Negative baseline-line drift was blocked.' -ForegroundColor Green

    Write-Host 'Public-text neutrality gate tests passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
