[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\zapret2-oneclick",
    [switch]$SkipSelection,
    [switch]$NoStart,
    [switch]$Rescan,
    [switch]$Rollback,
    [switch]$TestFailAfterPublish,
    [switch]$TestFailAfterSelection
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

$installerLock = $null
$stagedRoot = $null
$transaction = $null
$takeoverStarted = $false
$serviceSnapshot = $null
try {
    Write-Host 'zapret2-oneclick: installer' -ForegroundColor Cyan
    Assert-Z2OSupportedPlatform

    if ($Rollback) {
        $installerLock = Enter-Z2OInstallerLock -InstallRoot $InstallRoot
        Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'manual-rollback'
        Restore-Z2OPreviousConfig -InstallRoot $InstallRoot
        if (-not $NoStart) { Start-Z2OService }
        exit 0
    }
    if (($TestFailAfterPublish -or $TestFailAfterSelection) -and $env:Z2O_ENABLE_TEST_HOOKS -ne '1') {
        throw 'The failure-injection hook is disabled.'
    }

    # Validate and stage every byte of the new payload while the current
    # service is still running. A corrupt archive or incompatible config must
    # not cause downtime.
    Test-Z2OVendorManifest -SourceRoot $sourceRoot
    $stagedRoot = New-Z2OPayloadStage -SourceRoot $sourceRoot -InstallRoot $InstallRoot
    Test-Z2ONewPayloadPreflight -StagedRoot $stagedRoot -InstallRoot $InstallRoot

    $installerLock = Enter-Z2OInstallerLock -InstallRoot $InstallRoot
    Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'recovering-stale-transaction'
    Restore-Z2OStaleUpgradeIfNeeded -InstallRoot $InstallRoot

    $serviceSnapshot = Get-Z2OServiceSnapshot -InstallRoot $InstallRoot
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
    Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'takeover'
    $takeoverStarted = $true
    Stop-Z2OConflictingProcesses -InstallRoot $InstallRoot
    if ($winDivertOwnership -eq 'owned' -and (Test-Path -LiteralPath $InstallRoot)) {
        # A failed/retired selection can leave our kernel driver loaded and its
        # payload .sys locked. Stop our owned driver before atomically replacing
        # the payload; never touch a driver recorded as preexisting.
        Set-Z2OWinDivertOwnership -InstallRoot $InstallRoot -Ownership owned
        Remove-Z2OWinDivertService -InstallRoot $InstallRoot
    }
    $transaction = New-Z2OUpgradeTransaction -InstallRoot $InstallRoot -StagedRoot $stagedRoot `
        -ServiceSnapshot $serviceSnapshot
    $stagedRoot = $null
    Set-Z2OWinDivertOwnership -InstallRoot $InstallRoot -Ownership $winDivertOwnership
    Test-Z2OVendorManifest -SourceRoot $InstallRoot
    if ($TestFailAfterPublish) { throw 'Induced failure after payload publication.' }

    if (-not $SkipSelection) {
        Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'selection'
        Backup-Z2OActiveConfig -InstallRoot $InstallRoot
        Invoke-Z2OStrategySelection -InstallRoot $InstallRoot -Rescan:$Rescan
        Set-Z2OUpgradePhase -Transaction $transaction -Phase 'selection-complete'
        if ($TestFailAfterSelection) { throw 'Induced failure after strategy selection.' }
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
    Complete-Z2OUpgradeTransaction -Transaction $transaction
    $transaction = $null
    Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'complete'

    Write-Host "Installed successfully to $InstallRoot" -ForegroundColor Green
    exit 0
}
catch {
    $failure = $_
    $rollbackFailure = $null
    try {
        if ($transaction) {
            Restore-Z2OUpgradeTransaction -Transaction $transaction
            $transaction = $null
        }
        elseif ($takeoverStarted -and $serviceSnapshot -and $serviceSnapshot.HadWorkingConfig -and
            (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
            $activeConfig = Join-Path $InstallRoot 'runtime\active.conf'
            Test-Z2OWinwsConfig -InstallRoot $InstallRoot -ConfigPath $activeConfig
            Install-Z2OService -InstallRoot $InstallRoot -ConfigPath $activeConfig
            Start-Z2OService
            Assert-Z2OServiceRunning
        }
    }
    catch { $rollbackFailure = $_ }
    if ($rollbackFailure) {
        Write-Error -Message "Installation failed: $failure`nAutomatic rollback also failed: $rollbackFailure" -ErrorAction Continue
    }
    else {
        Write-Error -ErrorRecord $failure -ErrorAction Continue
    }
    exit 1
}
finally {
    if ($stagedRoot -and (Test-Path -LiteralPath $stagedRoot)) {
        Remove-Item -LiteralPath $stagedRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Exit-Z2OInstallerLock -Lock $installerLock
    try { Stop-Transcript | Out-Null } catch { }
}
