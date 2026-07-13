[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\zapret2-oneclick",
    [switch]$SkipSelection,
    [switch]$NoStart,
    [switch]$Rescan,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'Zapret2OneClick.psm1'
Import-Module $modulePath -Force

if (-not (Test-Z2OAdministrator)) {
    Invoke-Z2OElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
    exit $LASTEXITCODE
}

$sourceRoot = Split-Path -Parent $PSScriptRoot
$logRoot = "$InstallRoot.logs"
$logPath = New-Z2OLogPath -Root $logRoot -Prefix 'install'
Start-Transcript -Path $logPath -Append | Out-Null

try {
    Write-Host 'zapret2-oneclick: installer' -ForegroundColor Cyan
    Assert-Z2OSupportedPlatform

    if ($Rollback) {
        Restore-Z2OPreviousConfig -InstallRoot $InstallRoot
        if (-not $NoStart) { Start-Z2OService }
        exit 0
    }

    Test-Z2OVendorManifest -SourceRoot $sourceRoot
    $winDivertOwnership = Get-Z2OWinDivertOwnership -InstallRoot $InstallRoot
    if ($winDivertOwnership -eq 'unknown') {
        # A running installation predating the ownership marker owns the driver.
        # Otherwise an already registered WinDivert service belongs to another product.
        $winDivertOwnership = if (Test-Z2OScServicePresent -Name 'zapret2-oneclick') {
            'owned'
        } elseif (Test-Z2OScServicePresent -Name 'windivert') {
            'preexisting'
        } else {
            'owned'
        }
    }
    Stop-Z2OConflictingProcesses
    Install-Z2OPayload -SourceRoot $sourceRoot -InstallRoot $InstallRoot
    Set-Z2OWinDivertOwnership -InstallRoot $InstallRoot -Ownership $winDivertOwnership
    Test-Z2OVendorManifest -SourceRoot $InstallRoot

    if (-not $SkipSelection) {
        Backup-Z2OActiveConfig -InstallRoot $InstallRoot
        Invoke-Z2OStrategySelection -InstallRoot $InstallRoot -Rescan:$Rescan
    }

    $activeConfig = Join-Path $InstallRoot 'runtime\active.conf'
    if (-not (Test-Path -LiteralPath $activeConfig -PathType Leaf)) {
        throw "No active configuration exists at $activeConfig. Run selection or provide a validated active.conf."
    }

    Test-Z2OWinwsConfig -InstallRoot $InstallRoot -ConfigPath $activeConfig
    Install-Z2OService -InstallRoot $InstallRoot -ConfigPath $activeConfig
    if (-not $NoStart) {
        Start-Z2OService
        Assert-Z2OServiceRunning
    }

    Write-Host "Installed successfully to $InstallRoot" -ForegroundColor Green
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
finally {
    try { Stop-Transcript | Out-Null } catch { }
}
