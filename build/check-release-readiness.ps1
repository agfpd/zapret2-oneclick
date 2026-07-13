[CmdletBinding()]
param([string]$Root = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$lockPath = Join-Path $Root 'compliance\cygwin-packages.lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($lock.status -ne 'complete' -or $lock.packages.Count -eq 0) {
    throw 'Release blocked: Cygwin corresponding-source lock is incomplete.'
}

Import-Module (Join-Path $Root 'launcher\Zapret2OneClick.psm1') -Force
Test-Z2OVendorManifest -SourceRoot $Root
Write-Host 'Release inputs are ready.' -ForegroundColor Green

