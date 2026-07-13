[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\zapret2-oneclick",
    [switch]$KeepLogs
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Zapret2OneClick.psm1') -Force

if (-not (Test-Z2OAdministrator)) {
    Invoke-Z2OElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
    exit $LASTEXITCODE
}

try {
    Remove-Z2OService
    Remove-Z2OWinDivertService

    if (Test-Path -LiteralPath $InstallRoot) {
        if ($KeepLogs) {
            Get-ChildItem -LiteralPath $InstallRoot -Force |
                Where-Object Name -ne 'runtime' |
                Remove-Item -Recurse -Force
        }
        else {
            Remove-Item -LiteralPath $InstallRoot -Recurse -Force
        }
    }
    $logRoot = "$InstallRoot.logs"
    if (-not $KeepLogs -and (Test-Path -LiteralPath $logRoot)) {
        Remove-Item -LiteralPath $logRoot -Recurse -Force
    }
    Write-Host 'zapret2-oneclick was removed.' -ForegroundColor Green
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
