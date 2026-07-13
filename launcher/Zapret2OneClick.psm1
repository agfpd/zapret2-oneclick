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

function Stop-Z2OConflictingProcesses {
    param([string]$ServiceName = $script:Z2OServiceName)
    Remove-Z2OService -Name $ServiceName
    $conflicts = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('winws.exe', 'winws2.exe', 'goodbyedpi.exe') }
    if ($conflicts) {
        $details = $conflicts | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.ProcessId }
        throw "Stop other DPI bypass processes before installation: $($details -join ', ')"
    }
}

function Install-Z2OPayload {
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$InstallRoot)
    # Keep staging as a sibling. If replacement fails, it must never be moved
    # inside the existing payload and mistaken for a successful install.
    $staging = $InstallRoot + '.staging.' + [Guid]::NewGuid().ToString('N')
    try {
        New-Item -ItemType Directory -Path $staging -Force | Out-Null
        foreach ($name in @('vendor', 'config', 'launcher', 'checksums', 'patches', 'THIRD_PARTY_NOTICES.md')) {
            $source = Join-Path $SourceRoot $name
            if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $staging -Recurse -Force }
        }
        New-Item -ItemType Directory -Path (Join-Path $staging 'runtime\logs') -Force | Out-Null
        if (Test-Path -LiteralPath $InstallRoot) {
            $runtimeSource = Join-Path $InstallRoot 'runtime'
            if (Test-Path -LiteralPath $runtimeSource) {
                $runtimeDestination = Join-Path $staging 'runtime'
                Get-ChildItem -LiteralPath $runtimeSource -Force |
                    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $runtimeDestination -Recurse -Force }
            }
            Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $InstallRoot) {
                throw "Could not replace the existing payload at $InstallRoot."
            }
        }
        Move-Item -LiteralPath $staging -Destination $InstallRoot -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
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
