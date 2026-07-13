Set-StrictMode -Version 2.0

$script:Z2OServiceName = 'zapret2-oneclick'
$script:Z2ODisplayName = 'zapret2 one-click DPI bypass'
$script:Z2ORelativeWinws = 'vendor\zapret2\service\winws2.exe'

function Test-Z2OAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-Z2OArgumentList {
    param([hashtable]$BoundParameters)
    $args = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $BoundParameters.GetEnumerator()) {
        $name = '-' + $entry.Key
        if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($entry.Value.IsPresent) { $args.Add($name) }
        }
        elseif ($null -ne $entry.Value) {
            $escaped = ([string]$entry.Value).Replace('"', '\"')
            $args.Add($name)
            $args.Add(('"{0}"' -f $escaped))
        }
    }
    return $args.ToArray()
}

function Invoke-Z2OElevated {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [hashtable]$BoundParameters = @{}
    )
    $childArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $ScriptPath))
    $childArgs += ConvertTo-Z2OArgumentList -BoundParameters $BoundParameters
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $childArgs -Wait -PassThru
    $global:LASTEXITCODE = $process.ExitCode
}

function Assert-Z2OSupportedPlatform {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'Only x86_64 Windows is supported.' }
    $version = [Environment]::OSVersion.Version
    if ($version.Major -lt 10) { throw "Windows 10 or 11 is required; detected $version." }
    if (-not [Environment]::Is64BitProcess) { throw 'Run the 64-bit Windows PowerShell host.' }
}

function New-Z2OLogPath {
    param([Parameter(Mandatory)][string]$Root, [string]$Prefix = 'run')
    $logDir = Join-Path $Root 'runtime\logs'
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    return Join-Path $logDir ('{0}-{1}.log' -f $Prefix, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

function Get-Z2OSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-Z2OVendorManifest {
    param([Parameter(Mandatory)][string]$SourceRoot)
    $manifestPath = Join-Path $SourceRoot 'checksums\vendor.sha256'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Missing manifest: $manifestPath" }

    $failures = New-Object System.Collections.Generic.List[string]
    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
            $failures.Add("Malformed manifest line: $line")
            continue
        }
        $expected = $Matches[1].ToLowerInvariant()
        $relative = $Matches[2].Replace('/', [IO.Path]::DirectorySeparatorChar)
        $fullPath = Join-Path $SourceRoot $relative
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $failures.Add("Missing: $relative")
            continue
        }
        $actual = Get-Z2OSha256 -Path $fullPath
        if ($actual -ne $expected) { $failures.Add("Hash mismatch: $relative") }
    }
    if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
}

function Get-Z2OInstallerLockPath {
    return (Join-Path $env:ProgramData 'zapret2-oneclick.install-lock')
}

function Get-Z2OUpgradeStatePath {
    param([Parameter(Mandatory)][string]$InstallRoot)
    return ($InstallRoot + '.upgrade-state.json')
}

function Write-Z2OJsonAtomic {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    $temporary = $Path + '.tmp.' + [Guid]::NewGuid().ToString('N')
    try {
        $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-Z2OProcessIdentity {
    param([Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][long]$StartTimeUtcTicks)
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $process) { return $false }
    try { return $process.StartTime.ToUniversalTime().Ticks -eq $StartTimeUtcTicks }
    catch { return $false }
}

function Enter-Z2OInstallerLock {
    param([Parameter(Mandatory)][string]$InstallRoot, [int]$WaitSeconds = 3)
    $lockRoot = Get-Z2OInstallerLockPath
    $ownerPath = Join-Path $lockRoot 'owner.json'
    $acquired = $false
    try {
        $deadline = (Get-Date).AddSeconds($WaitSeconds)
        do {
            try {
                New-Item -ItemType Directory -Path $lockRoot -ErrorAction Stop | Out-Null
                $acquired = $true
                break
            }
            catch { Start-Sleep -Milliseconds 200 }
        } while ((Get-Date) -lt $deadline)

        if (-not $acquired) {
            $holder = $null
            try { $holder = Get-Content -LiteralPath $ownerPath -Raw -ErrorAction Stop | ConvertFrom-Json }
            catch { }
            if (-not $holder) {
                $lockAge = (Get-Date) - (Get-Item -LiteralPath $lockRoot -ErrorAction Stop).LastWriteTime
                if ($lockAge.TotalSeconds -lt 30) {
                    throw 'Another installer owns the machine-wide lock, but its identity is not available yet. Try again in 30 seconds.'
                }
            }
            $holderIsLive = $holder -and
                (Test-Z2OProcessIdentity -ProcessId ([int]$holder.processId) -StartTimeUtcTicks ([long]$holder.startTimeUtcTicks))
            if ($holderIsLive) {
                $holderProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [int]$holder.processId) -ErrorAction SilentlyContinue
                if (-not $holderProcess -or $holderProcess.CommandLine -notmatch '(?i)[\\/]launcher[\\/]Install\.ps1(?:\s|\"|$)') {
                    throw 'The installer lock holder is not a verified zapret2-oneclick installer; refusing to terminate it.'
                }
                Write-Warning ("Taking over an older installer process (PID {0}, phase {1})." -f $holder.processId, $holder.phase)
                & "$env:SystemRoot\System32\taskkill.exe" /PID ([int]$holder.processId) /T /F 2>&1 | Out-Null
            }
            else {
                Write-Warning 'Removing a stale installer lock whose owner is no longer running.'
            }
            Remove-Item -LiteralPath $lockRoot -Recurse -Force -ErrorAction Stop
            $deadline = (Get-Date).AddSeconds(15)
            do {
                try {
                    New-Item -ItemType Directory -Path $lockRoot -ErrorAction Stop | Out-Null
                    $acquired = $true
                    break
                }
                catch { Start-Sleep -Milliseconds 200 }
            } while ((Get-Date) -lt $deadline)
            if (-not $acquired) { throw 'The previous installer did not release the machine-wide lock.' }
        }

        $process = Get-Process -Id $PID
        $owner = [ordered]@{
            schemaVersion = 1
            processId = $PID
            startTimeUtcTicks = $process.StartTime.ToUniversalTime().Ticks
            installRoot = [IO.Path]::GetFullPath($InstallRoot)
            phase = 'preflight-complete'
            updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        }
        Write-Z2OJsonAtomic -Value $owner -Path $ownerPath
        return [pscustomobject]@{ Path = $lockRoot; OwnerPath = $ownerPath; Owner = $owner }
    }
    catch {
        if ($acquired) { Remove-Item -LiteralPath $lockRoot -Recurse -Force -ErrorAction SilentlyContinue }
        throw
    }
}

function Set-Z2OInstallerLockPhase {
    param([Parameter(Mandatory)]$Lock, [Parameter(Mandatory)][string]$Phase)
    $Lock.Owner.phase = $Phase
    $Lock.Owner.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
    Write-Z2OJsonAtomic -Value $Lock.Owner -Path $Lock.OwnerPath
}

function Exit-Z2OInstallerLock {
    param($Lock)
    if (-not $Lock) { return }
    try {
        $owner = $null
        try { $owner = Get-Content -LiteralPath $Lock.OwnerPath -Raw -ErrorAction Stop | ConvertFrom-Json }
        catch { }
        if ($owner -and [int]$owner.processId -eq $PID -and
            [long]$owner.startTimeUtcTicks -eq [long]$Lock.Owner.startTimeUtcTicks) {
            Remove-Item -LiteralPath $Lock.Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    finally { }
}

function Invoke-Z2OSc {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowFailure)
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    $code = $LASTEXITCODE
    if (-not $AllowFailure -and $code -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed ($code): $($output -join ' ')"
    }
    return [pscustomobject]@{ ExitCode = $code; Output = $output }
}

function Test-Z2OScServicePresent {
    param([Parameter(Mandatory)][string]$Name)
    return (Invoke-Z2OSc -Arguments @('query', $Name) -AllowFailure).ExitCode -eq 0
}

function Get-Z2OWinDivertOwnership {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $path = Join-Path $InstallRoot 'runtime\windivert-ownership.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return 'unknown' }
    $value = (Get-Content -LiteralPath $path -Raw).Trim()
    if ($value -notin @('owned', 'preexisting')) { return 'unknown' }
    return $value
}

function Set-Z2OWinDivertOwnership {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][ValidateSet('owned', 'preexisting')][string]$Ownership
    )
    $path = Join-Path $InstallRoot 'runtime\windivert-ownership.txt'
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    Set-Content -LiteralPath $path -Value $Ownership -Encoding ASCII
}

function Wait-Z2OServiceAbsent {
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSeconds = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $query = Invoke-Z2OSc -Arguments @('query', $Name) -AllowFailure
        if ($query.ExitCode -ne 0) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Service $Name is still present after $TimeoutSeconds seconds."
}

function Remove-Z2OService {
    param([string]$Name = $script:Z2OServiceName)
    $query = Invoke-Z2OSc -Arguments @('query', $Name) -AllowFailure
    if ($query.ExitCode -ne 0) { return }
    Invoke-Z2OSc -Arguments @('stop', $Name) -AllowFailure | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    do {
        $state = Invoke-Z2OSc -Arguments @('query', $Name) -AllowFailure
        if (($state.Output -join "`n") -notmatch 'STOP_PENDING|RUNNING') { break }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    Invoke-Z2OSc -Arguments @('delete', $Name) | Out-Null
    Wait-Z2OServiceAbsent -Name $Name
}

function Install-Z2OService {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$ConfigPath
    )
    Remove-Z2OService -Name $script:Z2OServiceName
    $winws = Join-Path $InstallRoot $script:Z2ORelativeWinws
    $binPath = ('"{0}" @"{1}"' -f $winws, $ConfigPath)
    Invoke-Z2OSc -Arguments @(
        'create', $script:Z2OServiceName,
        'type=', 'own',
        'start=', 'auto',
        'error=', 'normal',
        'binPath=', $binPath,
        'DisplayName=', $script:Z2ODisplayName
    ) | Out-Null
    Invoke-Z2OSc -Arguments @('description', $script:Z2OServiceName, 'Private zapret2 DPI bypass service') | Out-Null
    Invoke-Z2OSc -Arguments @('failure', $script:Z2OServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000') | Out-Null
    Invoke-Z2OSc -Arguments @('failureflag', $script:Z2OServiceName, '1') | Out-Null
}

function Start-Z2OService {
    param([string]$Name = $script:Z2OServiceName)
    $result = Invoke-Z2OSc -Arguments @('start', $Name) -AllowFailure
    if ($result.ExitCode -ne 0 -and ($result.Output -join ' ') -notmatch '1056') {
        throw "Could not start ${Name}: $($result.Output -join ' ')"
    }
}

function Assert-Z2OServiceRunning {
    param([string]$Name = $script:Z2OServiceName, [int]$TimeoutSeconds = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $result = Invoke-Z2OSc -Arguments @('query', $Name) -AllowFailure
        if (($result.Output -join "`n") -match 'STATE\s+:\s+4\s+RUNNING') { return }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Service $Name did not reach RUNNING."
}

function Remove-Z2OWinDivertService {
    param([Parameter(Mandatory)][string]$InstallRoot)
    if ((Get-Z2OWinDivertOwnership -InstallRoot $InstallRoot) -ne 'owned') {
        Write-Warning 'WinDivert driver service was left in place because this installation did not record ownership of it.'
        return
    }
    $otherConsumers = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('winws.exe', 'winws2.exe', 'goodbyedpi.exe') }
    if ($otherConsumers) {
        Write-Warning 'WinDivert driver service was left in place because another DPI bypass process is running.'
        return
    }
    $query = Invoke-Z2OSc -Arguments @('query', 'windivert') -AllowFailure
    if ($query.ExitCode -eq 0) {
        Invoke-Z2OSc -Arguments @('stop', 'windivert') -AllowFailure | Out-Null
        Invoke-Z2OSc -Arguments @('delete', 'windivert') -AllowFailure | Out-Null
        Wait-Z2OServiceAbsent -Name 'windivert'
    }
}

function Test-Z2OPathUnderRoot {
    param([string]$Path, [Parameter(Mandatory)][string]$Root)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $rootPrefix = ([IO.Path]::GetFullPath($Root)).TrimEnd('\') + '\'
    try { return ([IO.Path]::GetFullPath($Path)).StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) }
    catch { return $false }
}

function Get-Z2OInstallProcesses {
    param([Parameter(Mandatory)][string]$InstallRoot)
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        Test-Z2OPathUnderRoot -Path $_.ExecutablePath -Root $InstallRoot
    })
}

function Get-Z2OForeignConflictingProcesses {
    param([Parameter(Mandatory)][string]$InstallRoot)
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in @('winws.exe', 'winws2.exe', 'goodbyedpi.exe') -and
        -not (Test-Z2OPathUnderRoot -Path $_.ExecutablePath -Root $InstallRoot)
    })
}

function Assert-Z2ONoForeignConflicts {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $conflicts = @(Get-Z2OForeignConflictingProcesses -InstallRoot $InstallRoot)
    if ($conflicts.Count -gt 0) {
        $details = $conflicts | ForEach-Object { '{0} (PID {1}, {2})' -f $_.Name, $_.ProcessId, $_.ExecutablePath }
        throw "Stop other DPI bypass processes before installation: $($details -join ', ')"
    }
}

function Stop-Z2OExistingInstallerProcesses {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $byId = @{}
    foreach ($process in $all) { $byId[[int]$process.ProcessId] = $process }
    $private = @($all | Where-Object { Test-Z2OPathUnderRoot -Path $_.ExecutablePath -Root $InstallRoot })
    $parents = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($process in $private) {
        $cursor = $process
        for ($depth = 0; $depth -lt 12; $depth++) {
            $parentId = [int]$cursor.ParentProcessId
            if ($parentId -le 0 -or -not $byId.ContainsKey($parentId)) { break }
            $cursor = $byId[$parentId]
            if ([int]$cursor.ProcessId -eq $PID) { break }
            if ($cursor.Name -match '^(powershell|pwsh)\.exe$' -and
                $cursor.CommandLine -match '(?i)[\\/]launcher[\\/]Install\.ps1(?:\s|\"|$)') {
                [void]$parents.Add([int]$cursor.ProcessId)
                break
            }
        }
    }
    foreach ($parentId in $parents) {
        Write-Warning "Stopping an older installer process tree (PID $parentId)."
        & "$env:SystemRoot\System32\taskkill.exe" /PID $parentId /T /F 2>&1 | Out-Null
    }
}

function Stop-Z2OInstallProcesses {
    param([Parameter(Mandatory)][string]$InstallRoot, [int]$TimeoutSeconds = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $processes = @(Get-Z2OInstallProcesses -InstallRoot $InstallRoot)
        if ($processes.Count -eq 0) { return }
        foreach ($process in $processes) {
            & "$env:SystemRoot\System32\taskkill.exe" /PID ([int]$process.ProcessId) /T /F 2>&1 | Out-Null
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    $remaining = @(Get-Z2OInstallProcesses -InstallRoot $InstallRoot)
    if ($remaining.Count -gt 0) {
        $details = $remaining | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.ProcessId }
        throw "Could not stop existing private processes: $($details -join ', ')"
    }
}

function Stop-Z2OConflictingProcesses {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [string]$ServiceName = $script:Z2OServiceName
    )
    Stop-Z2OExistingInstallerProcesses -InstallRoot $InstallRoot
    Remove-Z2OService -Name $ServiceName
    Stop-Z2OInstallProcesses -InstallRoot $InstallRoot
    Assert-Z2ONoForeignConflicts -InstallRoot $InstallRoot
}

function Copy-Z2OPayloadTree {
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$DestinationRoot)
    New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
    foreach ($name in @('vendor', 'config', 'launcher', 'checksums', 'patches', 'THIRD_PARTY_NOTICES.md')) {
        $source = Join-Path $SourceRoot $name
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $DestinationRoot -Recurse -Force }
    }
    New-Item -ItemType Directory -Path (Join-Path $DestinationRoot 'runtime\logs') -Force | Out-Null
}

function New-Z2OPayloadStage {
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$InstallRoot)
    $staging = $InstallRoot + '.staging.' + [Guid]::NewGuid().ToString('N')
    try {
        Copy-Z2OPayloadTree -SourceRoot $SourceRoot -DestinationRoot $staging
        Test-Z2OVendorManifest -SourceRoot $staging
        return $staging
    }
    catch {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Copy-Z2ORuntimeState {
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$DestinationRoot)
    $runtimeSource = Join-Path $SourceRoot 'runtime'
    if (-not (Test-Path -LiteralPath $runtimeSource -PathType Container)) { return }
    $runtimeDestination = Join-Path $DestinationRoot 'runtime'
    New-Item -ItemType Directory -Path $runtimeDestination -Force | Out-Null
    Get-ChildItem -LiteralPath $runtimeSource -Force |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $runtimeDestination -Recurse -Force }
}

function Test-Z2ONewPayloadPreflight {
    param(
        [Parameter(Mandatory)][string]$StagedRoot,
        [Parameter(Mandatory)][string]$InstallRoot
    )
    Test-Z2OVendorManifest -SourceRoot $StagedRoot
    $servicesPath = Join-Path $StagedRoot 'config\services.json'
    $catalog = Get-Content -LiteralPath $servicesPath -Raw | ConvertFrom-Json
    if ($catalog.scopeStatus -ne 'final' -or $catalog.groups.Count -eq 0) {
        throw 'The new payload has no finalized service catalog.'
    }
    Assert-Z2ONoForeignConflicts -InstallRoot $InstallRoot

    $preflightConfig = Join-Path $StagedRoot 'runtime\preflight-active.conf'
    $existingConfig = Join-Path $InstallRoot 'runtime\active.conf'
    if (Test-Path -LiteralPath $existingConfig -PathType Leaf) {
        Copy-Item -LiteralPath $existingConfig -Destination $preflightConfig -Force
    }
    else {
        @('--wf-l3=ipv4', '--wf-tcp-out=443') | Set-Content -LiteralPath $preflightConfig -Encoding ASCII
    }
    try { Test-Z2OWinwsConfig -InstallRoot $StagedRoot -ConfigPath $preflightConfig }
    finally { Remove-Item -LiteralPath $preflightConfig -Force -ErrorAction SilentlyContinue }
}

function Get-Z2OServiceSnapshot {
    param([string]$Name = $script:Z2OServiceName, [Parameter(Mandatory)][string]$InstallRoot)
    $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        WasPresent = $null -ne $service
        WasRunning = $null -ne $service -and $service.State -eq 'Running'
        HadWorkingConfig = (Test-Path -LiteralPath (Join-Path $InstallRoot 'runtime\active.conf') -PathType Leaf)
    }
}

function New-Z2OUpgradeTransaction {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$StagedRoot,
        [Parameter(Mandatory)]$ServiceSnapshot
    )
    $backupRoot = $InstallRoot + '.rollback.' + [Guid]::NewGuid().ToString('N')
    $statePath = Get-Z2OUpgradeStatePath -InstallRoot $InstallRoot
    $state = [ordered]@{
        schemaVersion = 1
        installRoot = [IO.Path]::GetFullPath($InstallRoot)
        stagedRoot = [IO.Path]::GetFullPath($StagedRoot)
        backupRoot = [IO.Path]::GetFullPath($backupRoot)
        wasServicePresent = [bool]$ServiceSnapshot.WasPresent
        wasServiceRunning = [bool]$ServiceSnapshot.WasRunning
        hadWorkingConfig = [bool]$ServiceSnapshot.HadWorkingConfig
        phase = 'prepared'
        updatedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Z2OJsonAtomic -Value $state -Path $statePath
    $transaction = [pscustomobject]@{ State = $state; StatePath = $statePath }
    try {
        if (Test-Path -LiteralPath $InstallRoot) {
            Copy-Z2ORuntimeState -SourceRoot $InstallRoot -DestinationRoot $StagedRoot
            Move-Item -LiteralPath $InstallRoot -Destination $backupRoot -ErrorAction Stop
        }
        $state.phase = 'old-moved'
        $state.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        Write-Z2OJsonAtomic -Value $state -Path $statePath
        Move-Item -LiteralPath $StagedRoot -Destination $InstallRoot -ErrorAction Stop
        $state.phase = 'new-published'
        $state.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        Write-Z2OJsonAtomic -Value $state -Path $statePath
        return $transaction
    }
    catch {
        $original = $_
        try { Restore-Z2OUpgradeTransaction -Transaction $transaction }
        catch { throw "Payload publication failed and rollback also failed: $original; rollback: $_" }
        throw $original
    }
}

function Set-Z2OUpgradePhase {
    param([Parameter(Mandatory)]$Transaction, [Parameter(Mandatory)][string]$Phase)
    $Transaction.State.phase = $Phase
    $Transaction.State.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
    Write-Z2OJsonAtomic -Value $Transaction.State -Path $Transaction.StatePath
}

function Restore-Z2OUpgradeTransaction {
    param([Parameter(Mandatory)]$Transaction, [switch]$SkipServiceActions)
    $state = $Transaction.State
    $installRoot = [string]$state.installRoot
    $backupRoot = [string]$state.backupRoot
    Write-Warning 'The update failed; restoring the previous working installation.'
    if (-not $SkipServiceActions) { Remove-Z2OService -Name $script:Z2OServiceName }
    Stop-Z2OInstallProcesses -InstallRoot $installRoot
    if (Test-Path -LiteralPath $backupRoot -PathType Container) {
        if (Test-Path -LiteralPath $installRoot -PathType Container) {
            if (-not $SkipServiceActions) {
                try { Remove-Z2OWinDivertService -InstallRoot $installRoot } catch { }
            }
            Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
        }
        Move-Item -LiteralPath $backupRoot -Destination $installRoot -ErrorAction Stop
    }
    if (-not $SkipServiceActions -and [bool]$state.hadWorkingConfig -and
        (Test-Path -LiteralPath $installRoot -PathType Container)) {
        $activeConfig = Join-Path $installRoot 'runtime\active.conf'
        Test-Z2OWinwsConfig -InstallRoot $installRoot -ConfigPath $activeConfig
        Install-Z2OService -InstallRoot $installRoot -ConfigPath $activeConfig
        Start-Z2OService
        Assert-Z2OServiceRunning
    }
    Remove-Item -LiteralPath ([string]$state.stagedRoot) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Transaction.StatePath -Force -ErrorAction SilentlyContinue
}

function Complete-Z2OUpgradeTransaction {
    param([Parameter(Mandatory)]$Transaction)
    Set-Z2OUpgradePhase -Transaction $Transaction -Phase 'service-running'
    Remove-Item -LiteralPath ([string]$Transaction.State.backupRoot) -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath ([string]$Transaction.State.backupRoot)) {
        Write-Warning 'The previous payload backup is still locked; it will be cleaned by the next installer run.'
        return
    }
    Remove-Item -LiteralPath $Transaction.StatePath -Force -ErrorAction SilentlyContinue
}

function Restore-Z2OStaleUpgradeIfNeeded {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $statePath = Get-Z2OUpgradeStatePath -InstallRoot $InstallRoot
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $transaction = [pscustomobject]@{ State = $state; StatePath = $statePath }
    if ($state.phase -eq 'service-running') {
        try {
            Assert-Z2OServiceRunning
            Remove-Item -LiteralPath ([string]$state.backupRoot) -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath ([string]$state.backupRoot)) {
                Write-Warning 'The completed update backup is still locked; keeping its recovery journal for the next run.'
                return
            }
            Remove-Item -LiteralPath $statePath -Force -ErrorAction Stop
            return
        }
        catch { }
    }
    Restore-Z2OUpgradeTransaction -Transaction $transaction
}

function Install-Z2OPayload {
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$InstallRoot)
    $staging = New-Z2OPayloadStage -SourceRoot $SourceRoot -InstallRoot $InstallRoot
    try {
        if (Test-Path -LiteralPath $InstallRoot) {
            Copy-Z2ORuntimeState -SourceRoot $InstallRoot -DestinationRoot $staging
            Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction Stop
        }
        Move-Item -LiteralPath $staging -Destination $InstallRoot -ErrorAction Stop
        $staging = $null
    }
    finally {
        if ($staging -and (Test-Path -LiteralPath $staging)) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-Z2OWinwsConfig {
    param([Parameter(Mandatory)][string]$InstallRoot, [Parameter(Mandatory)][string]$ConfigPath)
    $winws = Join-Path $InstallRoot $script:Z2ORelativeWinws
    if (-not (Test-Path -LiteralPath $winws -PathType Leaf)) { throw "Missing winws2: $winws" }
    # When @config is used, winws2 ignores every other CLI argument. Create a
    # temporary config containing --dry-run instead of appending it on CLI.
    $dryConfig = Join-Path (Split-Path -Parent $ConfigPath) ('dry-run-{0}.conf' -f [Guid]::NewGuid().ToString('N'))
    try {
        @('--dry-run') + (Get-Content -LiteralPath $ConfigPath) |
            Set-Content -LiteralPath $dryConfig -Encoding ASCII
        $attempt = 0
        while ($true) {
            $attempt++
            $process = Start-Process -FilePath $winws -ArgumentList ('@"{0}"' -f $dryConfig) -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) { break }
            # A Cygwin child_copy failure can briefly leave Windows unable to
            # initialize another native process (STATUS_DLL_INIT_FAILED). The
            # same verified config succeeds once those handles are released.
            # Retry only that exact transient; every config/parser failure is
            # still reported immediately.
            if ($process.ExitCode -eq -1073741502 -and $attempt -lt 3) {
                Write-Warning "winws2 process initialization was temporarily unavailable; retrying dry-run ($attempt/3)."
                Start-Sleep -Seconds 2
                continue
            }
            throw "winws2 dry-run rejected $ConfigPath (exit $($process.ExitCode))."
        }
    }
    finally {
        Remove-Item -LiteralPath $dryConfig -Force -ErrorAction SilentlyContinue
    }
}

function Backup-Z2OActiveConfig {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $runtime = Join-Path $InstallRoot 'runtime'
    $active = Join-Path $runtime 'active.conf'
    if (Test-Path -LiteralPath $active) {
        Copy-Item -LiteralPath $active -Destination (Join-Path $runtime 'previous.conf') -Force
    }
    $selection = Join-Path $runtime 'selection.json'
    if (Test-Path -LiteralPath $selection) {
        Copy-Item -LiteralPath $selection -Destination (Join-Path $runtime 'previous-selection.json') -Force
    }
}

function Restore-Z2OPreviousConfig {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $runtime = Join-Path $InstallRoot 'runtime'
    $previous = Join-Path $runtime 'previous.conf'
    if (-not (Test-Path -LiteralPath $previous -PathType Leaf)) { throw 'No previous configuration is available.' }
    Remove-Z2OService -Name $script:Z2OServiceName
    Copy-Item -LiteralPath $previous -Destination (Join-Path $runtime 'active.conf') -Force
    Test-Z2OWinwsConfig -InstallRoot $InstallRoot -ConfigPath (Join-Path $runtime 'active.conf')
    Install-Z2OService -InstallRoot $InstallRoot -ConfigPath (Join-Path $runtime 'active.conf')
}

function Invoke-Z2OStrategySelection {
    param([Parameter(Mandatory)][string]$InstallRoot, [switch]$Rescan)
    $servicesPath = Join-Path $InstallRoot 'config\services.json'
    if (-not (Test-Path -LiteralPath $servicesPath -PathType Leaf)) { throw "Missing services catalog: $servicesPath" }
    $catalog = Get-Content -LiteralPath $servicesPath -Raw | ConvertFrom-Json
    if ($catalog.scopeStatus -ne 'final' -or $catalog.groups.Count -eq 0) {
        throw 'The target services catalog is not finalized yet. Use -SkipSelection only for infrastructure testing.'
    }
    if (-not $Rescan) {
        $active = Join-Path $InstallRoot 'runtime\active.conf'
        $selectionPath = Join-Path $InstallRoot 'runtime\selection.json'
        if ((Test-Path -LiteralPath $active -PathType Leaf) -and (Test-Path -LiteralPath $selectionPath -PathType Leaf)) {
            Write-Host 'Keeping the existing validated strategy. Use -Rescan to select again.'
            return
        }
    }

    $selections = @(Invoke-Z2OStrategySelectionCore -InstallRoot $InstallRoot -Catalog $catalog)
    $activeConfig = Write-Z2OActiveConfig -InstallRoot $InstallRoot -Catalog $catalog -Selections $selections
    $metadata = [ordered]@{
        schemaVersion = 1
        selectedAt = (Get-Date).ToUniversalTime().ToString('o')
        zapret2Version = 'v1.0.2'
        config = $activeConfig
        selections = $selections
        curatedProfiles = @('discord-media-stun')
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $InstallRoot 'runtime\selection.json') -Encoding UTF8
}

 . (Join-Path $PSScriptRoot 'Strategy.ps1')

Export-ModuleMember -Function *
