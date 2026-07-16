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
$serviceName = Get-Z2OServiceName -InstallRoot $InstallRoot
$isDefaultInstall = Test-Z2ODefaultInstallRoot -InstallRoot $InstallRoot
try {
    Write-Host 'zapret2-oneclick: installer' -ForegroundColor Cyan
    Assert-Z2OSupportedPlatform

    if ($Rollback) {
        $installerLock = Enter-Z2OInstallerLock -InstallRoot $InstallRoot
        Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'manual-rollback'
        Restore-Z2OPreviousConfig -InstallRoot $InstallRoot -ServiceName $serviceName
        if (-not $NoStart) {
            Start-Z2OService -Name $serviceName
            Assert-Z2OServiceRunning -Name $serviceName
        }
        exit 0
    }
    if (($TestFailAfterPublish -or $TestFailAfterSelection) -and $env:Z2O_ENABLE_TEST_HOOKS -ne '1') {
        throw 'The failure-injection hook is disabled.'
    }

    # Recover any interrupted publication before inspecting the active tree.
    # Lock/service identities are derived from InstallRoot, so a scratch-root
    # failure test cannot touch the production lock or service (H3).
    Test-Z2OVendorManifest -SourceRoot $sourceRoot
    $installerLock = Enter-Z2OInstallerLock -InstallRoot $InstallRoot
    Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'recovering-stale-transaction'
    Restore-Z2OStaleUpgradeIfNeeded -InstallRoot $InstallRoot

    # Validate, stage and select against the new payload while the current
    # service is still running. Selection is the slowest/fallible phase and
    # must not sit inside the takeover transaction (B5).
    $stagedRoot = New-Z2OPayloadStage -SourceRoot $sourceRoot -InstallRoot $InstallRoot
    if (Test-Path -LiteralPath $InstallRoot -PathType Container) {
        Copy-Z2ORuntimeState -SourceRoot $InstallRoot -DestinationRoot $stagedRoot
    }
    Test-Z2ONewPayloadPreflight -StagedRoot $stagedRoot -InstallRoot $InstallRoot
    if (-not $SkipSelection) {
        Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'selection-before-takeover'
        Invoke-Z2OStrategySelection -InstallRoot $stagedRoot -Rescan:$Rescan `
            -RunRoot (Get-Z2ORunRoot -InstallRoot $InstallRoot) -PublishedInstallRoot $InstallRoot
        if ($TestFailAfterSelection) { throw 'Induced failure after strategy selection.' }
    }

    $activeConfig = Join-Path $stagedRoot 'runtime\active.conf'
    if (-not (Test-Path -LiteralPath $activeConfig -PathType Leaf)) {
        throw "No active configuration exists at $activeConfig. Run selection or provide a validated active.conf."
    }
    Test-Z2OStagedPublishedConfig -StagedRoot $stagedRoot -PublishedRoot $InstallRoot -ConfigPath $activeConfig

    $serviceSnapshot = Get-Z2OServiceSnapshot -InstallRoot $InstallRoot -Name $serviceName
    $winDivertOwnership = if ($isDefaultInstall) {
        Get-Z2OWinDivertOwnership -InstallRoot $InstallRoot
    } else { 'preexisting' }
    if ($winDivertOwnership -eq 'unknown') {
        # A running installation predating the ownership marker owns the driver.
        # Otherwise an already registered WinDivert service belongs to another product.
        $winDivertOwnership = if (Test-Z2OScServicePresent -Name $serviceName) {
            'owned'
        } elseif (Test-Z2OScServicePresent -Name 'windivert') {
            'preexisting'
        } else {
            'owned'
        }
    }
    Set-Z2OInstallerLockPhase -Lock $installerLock -Phase 'takeover'
    $takeoverStarted = $true
    Stop-Z2OConflictingProcesses -InstallRoot $InstallRoot -ServiceName $serviceName
    if ($isDefaultInstall -and $winDivertOwnership -eq 'owned' -and (Test-Path -LiteralPath $InstallRoot)) {
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

    $activeConfig = Join-Path $InstallRoot 'runtime\active.conf'
    if (-not (Test-Path -LiteralPath $activeConfig -PathType Leaf)) {
        throw "No active configuration exists at $activeConfig. Run selection or provide a validated active.conf."
    }

    Test-Z2OWinwsConfig -InstallRoot $InstallRoot -ConfigPath $activeConfig
    Install-Z2OService -InstallRoot $InstallRoot -ConfigPath $activeConfig -Name $serviceName
    if (-not $NoStart) {
        Start-Z2OService -Name $serviceName
        Assert-Z2OServiceRunning -Name $serviceName
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
            Install-Z2OService -InstallRoot $InstallRoot -ConfigPath $activeConfig -Name $serviceName
            Start-Z2OService -Name $serviceName
            Assert-Z2OServiceRunning -Name $serviceName
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
