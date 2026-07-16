function ConvertTo-Z2OCygwinPath {
    param([Parameter(Mandatory)][string]$InstallRoot, [Parameter(Mandatory)][string]$Path)
    $cygpath = Join-Path $InstallRoot 'vendor\cygwin\bin\cygpath.exe'
    $value = & $cygpath -u -a $Path
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) {
        throw "cygpath failed for $Path"
    }
    return ([string]$value).Trim()
}

function Initialize-Z2OCygwinRuntime {
    param([Parameter(Mandatory)][string]$InstallRoot)
    # Compress-Archive omits empty directories. Never rely on the source
    # tree's empty vendor/cygwin/tmp surviving release packaging.
    New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'vendor\cygwin\tmp') -Force | Out-Null
}

function Get-Z2ORunRoot {
    param([Parameter(Mandatory)][string]$InstallRoot)
    # Selection diagnostics must survive payload rollback. Keep them beside the
    # transactional install tree, just like the installer transcript, rather
    # than copying them out after a failure has already started unwinding.
    return Join-Path ($InstallRoot + '.logs') 'runtime\runs'
}

function Get-Z2OIpMode {
    try {
        $defaultRoute = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction Stop |
            Where-Object { $_.RouteMetric -lt 9999 } |
            Select-Object -First 1
        if ($defaultRoute) { return '46' }
    }
    catch { }
    return '4'
}

function Read-Z2OMachineReport {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $raw = [string](Get-Content -LiteralPath $Path -Raw)
    if ($raw.Length -gt 0 -and -not $raw.EndsWith("`n")) {
        throw "Truncated blockcheck machine report: $Path"
    }
    $records = @()
    foreach ($line in @($raw -split "`r?`n" | Where-Object { $_.Length -gt 0 })) {
        $parts = $line -split "`t", 6
        if ($parts.Count -eq 5) {
            # v1 report compatibility: every record represented a successful strategy.
            $status = 'ok'
            $strategy = $parts[4].Trim()
        }
        elseif ($parts.Count -eq 6) {
            $status = $parts[4].Trim()
            $strategy = $parts[5].Trim()
        }
        else { throw "Malformed blockcheck machine report line: $line" }
        if ($status -notmatch '^(ok|not-blocked|no-strategy|infra-failure:[0-9]+)$') {
            throw "Unknown blockcheck machine status '$status': $line"
        }
        if ($status -eq 'ok' -and [string]::IsNullOrWhiteSpace($strategy)) {
            throw "Successful blockcheck record has no strategy: $line"
        }
        $records += [pscustomobject]@{
            Sequence = [int]$parts[0]
            Domain = $parts[1]
            Test = $parts[2]
            IpVersion = [int]$parts[3]
            Status = $status
            Strategy = $strategy
        }
    }
    return $records
}

function Stop-Z2OProcessTree {
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            # Refuse a PID-tree stop if an extremely fast reuse no longer
            # matches the retained process object we started.
            $current = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
            if (-not $current -or $current.StartTime -ne $Process.StartTime) { return }
            Stop-Z2OProcessTreeById -ProcessId $Process.Id
            if (-not $Process.WaitForExit(5000)) {
                $Process.Kill()
                $Process.WaitForExit(5000) | Out-Null
            }
        }
    }
    catch {
        try {
            if (-not $Process.HasExited) {
                $Process.Kill()
                $Process.WaitForExit(5000) | Out-Null
            }
        }
        catch { }
    }
}

function Get-Z2OInstallProcessIds {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $rootPrefix = ([IO.Path]::GetFullPath($InstallRoot)).TrimEnd('\') + '\'
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -ExpandProperty ProcessId)
}

function Stop-Z2OBlockcheckProcessTree {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$InstallRoot,
        [AllowEmptyCollection()][int[]]$BaselineProcessIds = @()
    )
    Stop-Z2OProcessTree -Process $Process

    # taskkill /T handles the ordinary live-parent case. If bash crashed after
    # orphaning curl/winws2, clean every new executable launched from this
    # private payload while preserving processes that existed before the run.
    Start-Sleep -Milliseconds 100
    $rootPrefix = ([IO.Path]::GetFullPath($InstallRoot)).TrimEnd('\') + '\'
    $orphans = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ExecutablePath -and
        $_.ExecutablePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        $BaselineProcessIds -notcontains [int]$_.ProcessId
    })
    foreach ($orphan in $orphans) {
        Stop-Process -Id $orphan.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Get-Z2OBlockcheckProgress {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Length = 0L; Tests = 0; Successes = 0 }
    }
    $item = Get-Item -LiteralPath $Path
    $tests = 0
    $successes = 0
    try {
        foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
            if ($line -like '- curl_test*') { $tests++ }
            if ($line -eq '!!!!! AVAILABLE !!!!!') { $successes++ }
        }
    }
    catch { }
    return [pscustomobject]@{ Length = [long]$item.Length; Tests = $tests; Successes = $successes }
}

function Test-Z2OCygwinFailureLog {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        return [bool](Select-String -LiteralPath $Path `
            -Pattern 'child_copy:.*failed|fork:.*failed|fork: Resource temporarily unavailable' -Quiet `
            -ErrorAction Stop)
    }
    catch { return $false }
}

function Get-Z2OCygwinFailureCount {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 0 }
    try {
        return @(Select-String -LiteralPath $Path `
            -Pattern 'child_copy:.*failed|fork:.*failed|fork: Resource temporarily unavailable' `
            -AllMatches -ErrorAction Stop).Count
    }
    catch { return 0 }
}

function Wait-Z2OBlockcheckProcess {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$StdoutPath,
        [Parameter(Mandatory)][string]$StderrPath,
        [Parameter(Mandatory)][string]$DisplayName,
        [ValidateRange(2, 7200)][int]$MaxRunSeconds = 900,
        [ValidateRange(2, 900)][int]$StallSeconds = 120,
        [ValidateRange(0, 14400)][int]$HardRunSeconds = 0,
        [ValidateRange(1, 60)][int]$HeartbeatSeconds = 15
    )
    $startedAt = Get-Date
    $softDeadline = $startedAt.AddSeconds($MaxRunSeconds)
    if ($HardRunSeconds -le 0) { $HardRunSeconds = $MaxRunSeconds + (2 * $StallSeconds) }
    $hardDeadline = $startedAt.AddSeconds($HardRunSeconds)
    $lastProgressAt = $startedAt
    $lastLength = 0L
    $lastSemanticProgressAt = $null
    $lastSeenTests = 0
    $lastSeenSuccesses = 0
    $leaseLength = 0L
    $leaseTests = 0
    $leaseSuccesses = 0
    $leaseRenewals = 0
    $nextHeartbeat = $HeartbeatSeconds
    while (-not $Process.WaitForExit(500)) {
        $now = Get-Date
        $elapsed = [int]($now - $startedAt).TotalSeconds
        $currentLength = if (Test-Path -LiteralPath $StdoutPath -PathType Leaf) {
            [long](Get-Item -LiteralPath $StdoutPath).Length
        } else { 0L }
        if ($currentLength -gt $lastLength) {
            $lastLength = $currentLength
            $lastProgressAt = $now
        }
        $stalledFor = [int]($now - $lastProgressAt).TotalSeconds
        # Close the race where the process exits just after the timed wait but
        # before a deadline check.
        $Process.Refresh()
        if ($Process.HasExited) { break }
        # child_copy/fork diagnostics can be emitted by a failed curl/winws2
        # descendant while blockcheck2 continues and finds valid strategies.
        # They are diagnostic signals, not a reason to kill the live bash root.
        if ($now -ge $hardDeadline) {
            return [pscustomobject]@{
                Status = 'hard-limit'; ElapsedSeconds = $elapsed; StalledSeconds = $stalledFor
                LeaseRenewals = $leaseRenewals
                CygwinFailures = (Get-Z2OCygwinFailureCount -Path $StderrPath)
            }
        }
        if ($stalledFor -ge $StallSeconds) {
            return [pscustomobject]@{
                Status = 'stall'; ElapsedSeconds = $elapsed; StalledSeconds = $stalledFor
                LeaseRenewals = $leaseRenewals
                CygwinFailures = (Get-Z2OCygwinFailureCount -Path $StderrPath)
            }
        }

        $deadlineReached = $now -ge $softDeadline
        $heartbeatDue = $elapsed -ge $nextHeartbeat
        if ($deadlineReached -or $heartbeatDue) {
            $progress = Get-Z2OBlockcheckProgress -Path $StdoutPath
            if ($progress.Tests -gt $lastSeenTests -or $progress.Successes -gt $lastSeenSuccesses) {
                $lastSemanticProgressAt = $now
            }
            $lastSeenTests = [Math]::Max($lastSeenTests, $progress.Tests)
            $lastSeenSuccesses = [Math]::Max($lastSeenSuccesses, $progress.Successes)

            if ($deadlineReached) {
                # MaxRunSeconds is a soft lease, not a kill-at-an-arbitrary-second
                # deadline. Renew it while blockcheck2 is still producing fresh
                # output (structured test/success counters are an additional
                # signal). A genuinely silent run is still terminated by the
                # independent stall watchdog.
                $outputSinceLease = $progress.Length -gt $leaseLength
                $outputIsRecent = $stalledFor -lt $StallSeconds
                $progressSinceLease = $progress.Tests -gt $leaseTests -or $progress.Successes -gt $leaseSuccesses
                $semanticProgressIsRecent = $null -ne $lastSemanticProgressAt -and `
                    ($now - $lastSemanticProgressAt).TotalSeconds -le $StallSeconds
                $canRenew = ($outputSinceLease -and $outputIsRecent) -or `
                    ($progressSinceLease -and $semanticProgressIsRecent)
                if (-not $canRenew) {
                    return [pscustomobject]@{
                        Status = 'limit'; ElapsedSeconds = $elapsed; StalledSeconds = $stalledFor
                        LeaseRenewals = $leaseRenewals
                        CygwinFailures = (Get-Z2OCygwinFailureCount -Path $StderrPath)
                    }
                }

                $leaseLength = $progress.Length
                $leaseTests = $progress.Tests
                $leaseSuccesses = $progress.Successes
                $leaseRenewals++
                $softDeadline = $now.AddSeconds($StallSeconds)
                Write-Host ("blockcheck2 passed the {0}s soft limit with fresh output; renewed for {1}s (tests={2}, successes={3}, renewals={4})." -f `
                    $MaxRunSeconds, $StallSeconds, $progress.Tests, $progress.Successes, $leaseRenewals) `
                    -ForegroundColor DarkGray
            }

            if ($heartbeatDue) {
                $deadlineElapsed = [int]($softDeadline - $startedAt).TotalSeconds
                Write-Host ("blockcheck2 progress: {0}, elapsed={1}s, soft limit={2}s, lease deadline={3}s, renewals={4}, tests={5}, successes={6}, last output {7}s ago. Live log: {8}" -f `
                    $DisplayName, $elapsed, $MaxRunSeconds, $deadlineElapsed, $leaseRenewals, `
                    $progress.Tests, $progress.Successes, $stalledFor, $StdoutPath) `
                    -ForegroundColor DarkGray
            }
            $nextHeartbeat += $HeartbeatSeconds
        }
    }
    # Flush redirected stream readers before inspecting files and ExitCode.
    $Process.WaitForExit()
    return [pscustomobject]@{
        Status = 'completed'
        ElapsedSeconds = [int]((Get-Date) - $startedAt).TotalSeconds
        StalledSeconds = 0
        LeaseRenewals = $leaseRenewals
        CygwinFailures = (Get-Z2OCygwinFailureCount -Path $StderrPath)
    }
}

function Invoke-Z2OBlockcheckRun {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][string]$TestName,
        [Parameter(Mandatory)][ValidateSet('quick', 'standard', 'force')][string]$ScanLevel,
        [Parameter(Mandatory)][int]$Repeats,
        [Parameter(Mandatory)][string]$RunLabel,
        [ValidateRange(2, 7200)][int]$MaxRunSeconds = 900,
        [ValidateRange(2, 900)][int]$StallSeconds = 120,
        [ValidateRange(0, 14400)][int]$AttemptWallSeconds = 0,
        [ValidateRange(0, 43200)][int]$OverallWallSeconds = 0,
        [ValidateRange(0, 3)][int]$CygwinRetries = 1,
        [ValidateRange(0, 100)][int]$MinimumSuccesses = 0,
        [switch]$AllowPartialAtLimit,
        [string]$BashPath,
        [string]$BlockcheckScriptPath,
        [string]$RunRoot,
        [hashtable]$EnvironmentOverrides = @{}
    )

    if (-not $RunRoot) { $RunRoot = Get-Z2ORunRoot -InstallRoot $InstallRoot }
    $runDirectory = Join-Path $RunRoot `
        ('{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmssfff'), $RunLabel)
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $machinePath = Join-Path $runDirectory 'machine.tsv'
    $stdoutPath = Join-Path $runDirectory 'blockcheck.log'
    $stderrPath = Join-Path $runDirectory 'blockcheck.err.log'

    $zapretRoot = Join-Path $InstallRoot 'vendor\zapret2'
    $bash = if ($BashPath) { $BashPath } else { Join-Path $InstallRoot 'vendor\cygwin\bin\bash.exe' }
    $cygBin = Join-Path $InstallRoot 'vendor\cygwin\bin'
    $cygLocalBin = Join-Path $InstallRoot 'vendor\cygwin\usr\local\bin'
    Initialize-Z2OCygwinRuntime -InstallRoot $InstallRoot
    $scriptPath = if ($BlockcheckScriptPath) {
        ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path $BlockcheckScriptPath
    } else {
        ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path (Join-Path $zapretRoot 'blockcheck2.sh')
    }
    $curlPath = ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path (Join-Path $cygLocalBin 'curl.exe')
    $machineCyg = ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path $machinePath
    $protocols = @($Group.protocols)
    if ($MinimumSuccesses -le 0) { $MinimumSuccesses = $Repeats }
    $variables = @{
        BATCH = '1'
        TEST = $TestName
        DOMAINS = (@($Group.probeDomains) -join ' ')
        # Public v1.x deliberately supports IPv4 capture only. Do not capture
        # IPv6 traffic into IPv4-only profiles (H2).
        IPVS = '4'
        ENABLE_HTTP = '0'
        ENABLE_HTTPS_TLS12 = $(if ($protocols -contains 'https-tls12') { '1' } else { '0' })
        ENABLE_HTTPS_TLS13 = $(if ($protocols -contains 'https-tls13') { '1' } else { '0' })
        ENABLE_HTTP3 = $(if ($protocols -contains 'quic') { '1' } else { '0' })
        REPEATS = [string]$Repeats
        PARALLEL = '0'
        SCANLEVEL = $ScanLevel
        SKIP_IPBLOCK = '1'
        CURL_MAX_TIME = '5'
        CURL_MAX_TIME_QUIC = '8'
        MIN_SUCCESSES = [string]$MinimumSuccesses
        QUICK_MAX_SUCCESSES = '2'
        CURL = $curlPath
        MACHINE_REPORT = $machineCyg
    }
    foreach ($entry in $EnvironmentOverrides.GetEnumerator()) {
        $variables[[string]$entry.Key] = [string]$entry.Value
    }

    $saved = @{}
    try {
        foreach ($entry in $variables.GetEnumerator()) {
            $saved[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        }
        $saved['PATH'] = $env:PATH
        $env:PATH = "$cygBin;$cygLocalBin;$env:SystemRoot\System32;$env:SystemRoot"

        if ($AttemptWallSeconds -le 0) { $AttemptWallSeconds = $MaxRunSeconds + (2 * $StallSeconds) }
        if ($OverallWallSeconds -le 0) {
            $OverallWallSeconds = (($CygwinRetries + 1) * $AttemptWallSeconds) + (2 * $CygwinRetries) + 5
        }
        $overallDeadline = (Get-Date).AddSeconds($OverallWallSeconds)
        $attempt = 0
        $totalLeaseRenewals = 0
        $finalStatus = $null
        while ($true) {
            $attempt++
            $remainingOverall = [int]($overallDeadline - (Get-Date)).TotalSeconds
            if ($remainingOverall -lt 2) {
                throw "blockcheck2 reached its ${OverallWallSeconds}s overall wall-clock ceiling for $($Group.id)."
            }
            Remove-Item -LiteralPath $stdoutPath, $stderrPath, $machinePath -Force -ErrorAction SilentlyContinue
            Write-Host ("blockcheck2: {0}, test={1}, scan={2}, repeats={3}, soft limit={4}s, stall limit={5}s" -f `
                $Group.displayName, $TestName, $ScanLevel, $Repeats, $MaxRunSeconds, $StallSeconds) -ForegroundColor Cyan
            $process = $null
            $outcome = $null
            $exitCode = $null
            $baselineProcessIds = @(Get-Z2OInstallProcessIds -InstallRoot $InstallRoot)
            try {
                $process = Start-Process -FilePath $bash -ArgumentList @($scriptPath) -PassThru `
                    -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -NoNewWindow
                # Force WinPS to retain the native process handle. Without this, polling
                # WaitForExit(timeout) can leave ExitCode unavailable after the process exits.
                $null = $process.Handle
                $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdoutPath -StderrPath $stderrPath `
                    -DisplayName $Group.displayName -MaxRunSeconds $MaxRunSeconds -StallSeconds $StallSeconds `
                    -HardRunSeconds ([Math]::Min($AttemptWallSeconds, $remainingOverall))
                $totalLeaseRenewals += [int]$outcome.LeaseRenewals
                if ($outcome.Status -eq 'completed') { $exitCode = $process.ExitCode }
            }
            finally {
                if ($process) {
                    Stop-Z2OBlockcheckProcessTree -Process $process -InstallRoot $InstallRoot `
                        -BaselineProcessIds $baselineProcessIds
                }
            }

            $partialRecords = @(Read-Z2OMachineReport -Path $machinePath)
            $cygwinFailed = [int]$outcome.CygwinFailures -gt 0
            if ($outcome.Status -eq 'completed' -and $exitCode -ne 0 -and $cygwinFailed) {
                $archiveSuffix = ".cygwin-attempt-$attempt"
                foreach ($path in @($stdoutPath, $stderrPath, $machinePath)) {
                    if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination "$path$archiveSuffix" -Force }
                }
                if ($AllowPartialAtLimit -and $partialRecords.Count -gt 0) {
                    Write-Warning ("blockcheck2 bash exited after a Cygwin child failure for {0}; preserving {1} complete machine records. Diagnostic: {2}{3}" -f `
                        $Group.id, $partialRecords.Count, $stderrPath, $archiveSuffix)
                    $finalStatus = 'partial'
                    break
                }
                if ($attempt -le $CygwinRetries) {
                    Write-Warning ("blockcheck2 bash exited after a Cygwin child failure; archiving attempt {0} and retrying with a fresh bounded lease. Diagnostic: {1}{2}" -f `
                        $attempt, $stderrPath, $archiveSuffix)
                    # Give terminated Cygwin descendants and security scanners a
                    # short quiet interval before creating a fresh process tree.
                    Start-Sleep -Seconds 2
                    continue
                }
                throw "Cygwin process creation failed repeatedly for $($Group.id). Diagnostic: $stderrPath$archiveSuffix"
            }
            if ($outcome.Status -eq 'stall') {
                throw "blockcheck2 made no log progress for ${StallSeconds}s for $($Group.id); its process tree was stopped. Live log: $stdoutPath"
            }
            if ($outcome.Status -in @('limit', 'hard-limit')) {
                if (-not $AllowPartialAtLimit -or $partialRecords.Count -eq 0) {
                    throw "blockcheck2 reached a bounded runtime limit for $($Group.id); its process tree was stopped. Live log: $stdoutPath"
                }
                Write-Warning ("blockcheck2 reached a bounded runtime limit for {0}; using {1} complete machine records." -f `
                    $Group.id, $partialRecords.Count)
                $finalStatus = 'partial'
                break
            }
            if ($null -eq $exitCode) {
                throw "blockcheck2 exit code was unavailable for $($Group.id). Logs: $stdoutPath, $stderrPath"
            }
            if ($exitCode -ne 0) {
                throw "blockcheck2 failed for $($Group.id), exit $exitCode. Logs: $stdoutPath, $stderrPath"
            }
            $finalStatus = 'completed'
            break
        }
    }
    finally {
        foreach ($entry in $saved.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        }
    }

    Get-Content -LiteralPath $stdoutPath | Write-Host
    if ((Get-Item -LiteralPath $stderrPath).Length -gt 0) { Get-Content -LiteralPath $stderrPath | Write-Warning }
    return [pscustomobject]@{
        Directory = $runDirectory
        MachinePath = $machinePath
        Records = @(Read-Z2OMachineReport -Path $machinePath)
        Status = $finalStatus
        Attempts = $attempt
        LeaseRenewals = $totalLeaseRenewals
        CygwinFailures = (Get-Z2OCygwinFailureCount -Path $stderrPath)
    }
}

function Get-Z2ORequiredTestNames {
    param([Parameter(Mandatory)]$Group, [Parameter(Mandatory)][ValidateSet('tls', 'quic')][string]$Kind)
    $protocols = @($Group.protocols)
    if ($Kind -eq 'quic') { return @('curl_test_http3') }
    $names = @()
    if ($protocols -contains 'https-tls12') { $names += 'curl_test_https_tls12' }
    if ($protocols -contains 'https-tls13') { $names += 'curl_test_https_tls13' }
    return $names
}

function Get-Z2OCommonCandidates {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][ValidateSet('tls', 'quic')][string]$Kind,
        [Parameter(Mandatory)][int]$IpVersion
    )
    $requiredTests = @(Get-Z2ORequiredTestNames -Group $Group -Kind $Kind)
    if ($requiredTests.Count -eq 0) { return @() }
    $requiredKeys = @()
    foreach ($domain in @($Group.probeDomains)) {
        foreach ($test in $requiredTests) { $requiredKeys += "$domain`t$test" }
    }

    $relevant = @($Records | Where-Object {
        $_.IpVersion -eq $IpVersion -and $requiredTests -contains $_.Test
    })
    $notBlockedKeys = @($relevant | Where-Object Status -eq 'not-blocked' |
        ForEach-Object { "$($_.Domain)`t$($_.Test)" } | Sort-Object -Unique)
    $bypassRequiredKeys = @($requiredKeys | Where-Object { $notBlockedKeys -notcontains $_ })
    if ($bypassRequiredKeys.Count -eq 0) {
        return @([pscustomobject]@{
            Kind = $Kind
            IpVersion = $IpVersion
            Strategy = ''
            Order = if ($relevant.Count -gt 0) { ($relevant | Measure-Object Sequence -Minimum).Minimum } else { 0 }
            BypassRequired = $false
        })
    }

    $eligible = @($relevant | Where-Object Status -eq 'ok')
    $result = @()
    foreach ($grouped in ($eligible | Group-Object Strategy)) {
        $keys = @($grouped.Group | ForEach-Object { "$($_.Domain)`t$($_.Test)" } | Sort-Object -Unique)
        $missing = @($bypassRequiredKeys | Where-Object { $keys -notcontains $_ })
        if ($missing.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind = $Kind
                IpVersion = $IpVersion
                Strategy = $grouped.Name
                Order = ($grouped.Group | Measure-Object Sequence -Minimum).Minimum
                BypassRequired = $true
            }
        }
    }
    return @($result | Sort-Object Order)
}

function Get-Z2OExpectedKinds {
    param([Parameter(Mandatory)]$Group)
    $protocols = @($Group.protocols)
    $kinds = @()
    if ($protocols -contains 'https-tls12' -or $protocols -contains 'https-tls13') { $kinds += 'tls' }
    if ($protocols -contains 'quic') { $kinds += 'quic' }
    return $kinds
}

function Get-Z2ORequiredKinds {
    param([Parameter(Mandatory)]$Group)
    $expected = @(Get-Z2OExpectedKinds -Group $Group)
    if ($Group.PSObject.Properties.Name -contains 'requiredKinds') {
        return @($Group.requiredKinds | Where-Object { $expected -contains $_ })
    }
    # TCP/TLS is the browser fallback and the only mandatory transport. QUIC
    # is explicitly degradable because many networks block UDP/443 (B7).
    return @($expected | Where-Object { $_ -eq 'tls' })
}

function Get-Z2OProductionPenalty {
    # An empty strategy is a legitimate value, not missing data: Get-Z2OCommonCandidates
    # emits a candidate with Strategy = '' and BypassRequired = $false when every required
    # probe of a kind reports not-blocked, i.e. the transport already works without bypass.
    # Mandatory alone rejects the empty string, so a favourable network (QUIC/TLS 1.3 not
    # blocked) crashed the candidate sort. AllowEmptyString admits that measured value.
    # The parameter is [object] rather than [string] on purpose: a [string] parameter coerces
    # $null to '' during binding, which would make absent data indistinguishable from a
    # measured "no bypass needed". [object] keeps Mandatory rejecting $null, so "measured and
    # empty" stays distinct from "not measured" and unset input still fails closed.
    param([Parameter(Mandatory)][AllowEmptyString()][object]$Strategy)
    # OOB candidates are useful diagnostics but can depend on blockcheck's
    # temporary SYN/range capture details. Prefer an equally stable ordinary
    # payload strategy for the long-running service.
    if ($Strategy -match '--lua-desync=oob(?:[:\s]|$)') { return 100 }
    return 0
}

function Get-Z2OCandidatesFromRun {
    param([Parameter(Mandatory)]$Run, [Parameter(Mandatory)]$Group)
    $versions = @($Run.Records | Select-Object -ExpandProperty IpVersion -Unique | Sort-Object)
    if ($versions.Count -eq 0) { $versions = @(4) }
    $all = @()
    foreach ($version in $versions) {
        foreach ($kind in @(Get-Z2OExpectedKinds -Group $Group)) {
            $found = @(Get-Z2OCommonCandidates -Records $Run.Records -Group $Group -Kind $kind -IpVersion $version)
            if ($kind -eq 'tls' -and $found.Count -eq 0 -and
                @($Group.protocols) -contains 'https-tls12' -and @($Group.protocols) -contains 'https-tls13') {
                $tls13Only = [pscustomobject]@{
                    probeDomains = @($Group.probeDomains)
                    protocols = @('https-tls13')
                }
                $found = @(Get-Z2OCommonCandidates -Records $Run.Records -Group $tls13Only -Kind $kind -IpVersion $version)
                foreach ($candidate in $found) {
                    $candidate | Add-Member -NotePropertyName Degraded -NotePropertyValue $true
                    $candidate | Add-Member -NotePropertyName ValidatedProtocols -NotePropertyValue @('https-tls13')
                }
            }
            foreach ($candidate in $found) {
                if (-not ($candidate.PSObject.Properties.Name -contains 'Degraded')) {
                    $candidate | Add-Member -NotePropertyName Degraded -NotePropertyValue $false
                    $protocolNames = if ($kind -eq 'tls') {
                        @($Group.protocols | Where-Object { $_ -like 'https-*' })
                    } else { @('quic') }
                    $candidate | Add-Member -NotePropertyName ValidatedProtocols -NotePropertyValue $protocolNames
                }
                if (-not ($candidate.PSObject.Properties.Name -contains 'BypassRequired')) {
                    $candidate | Add-Member -NotePropertyName BypassRequired -NotePropertyValue $true
                }
            }
            $all += $found
        }
    }
    return $all
}

function Get-Z2ODiscoveryPoolFromRun {
    param([Parameter(Mandatory)]$Run, [Parameter(Mandatory)]$Group)
    $all = @()
    $versions = @($Run.Records | Select-Object -ExpandProperty IpVersion -Unique | Sort-Object)
    foreach ($version in $versions) {
        foreach ($kind in @(Get-Z2OExpectedKinds -Group $Group)) {
            $requiredTests = @(Get-Z2ORequiredTestNames -Group $Group -Kind $kind)
            $eligible = @($Run.Records | Where-Object {
                $_.Status -eq 'ok' -and $_.IpVersion -eq $version -and $requiredTests -contains $_.Test
            })
            foreach ($grouped in ($eligible | Group-Object Strategy)) {
                $tests = @($grouped.Group | Select-Object -ExpandProperty Test -Unique)
                $protocols = @()
                if ($tests -contains 'curl_test_https_tls12') { $protocols += 'https-tls12' }
                if ($tests -contains 'curl_test_https_tls13') { $protocols += 'https-tls13' }
                if ($tests -contains 'curl_test_http3') { $protocols += 'quic' }
                $degraded = $kind -eq 'tls' -and
                    @($Group.protocols) -contains 'https-tls12' -and
                    @($Group.protocols) -contains 'https-tls13' -and
                    $tests -notcontains 'curl_test_https_tls12' -and
                    $tests -contains 'curl_test_https_tls13'
                $all += [pscustomobject]@{
                    Kind = $kind
                    IpVersion = $version
                    Strategy = $grouped.Name
                    Order = ($grouped.Group | Measure-Object Sequence -Minimum).Minimum
                    Degraded = [bool]$degraded
                    ValidatedProtocols = $protocols
                    BypassRequired = $true
                }
            }
        }
    }
    return $all
}

function Merge-Z2OCandidatePools {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates)
    $result = @()
    foreach ($grouped in ($Candidates | Group-Object { "$($_.IpVersion)`t$($_.Kind)`t$($_.Strategy)" })) {
        $first = $grouped.Group | Sort-Object Order | Select-Object -First 1
        $result += [pscustomobject]@{
            Kind = $first.Kind
            IpVersion = $first.IpVersion
            Strategy = $first.Strategy
            Order = ($grouped.Group | Measure-Object Order -Minimum).Minimum
            Priority = ($grouped.Group | ForEach-Object {
                if ($_.PSObject.Properties.Name -contains 'Priority') { [int]$_.Priority } else { 10 }
            } | Measure-Object -Minimum).Minimum
            Degraded = @($grouped.Group | Where-Object { $_.Degraded }).Count -eq $grouped.Count
            ValidatedProtocols = @($grouped.Group | ForEach-Object { @($_.ValidatedProtocols) } | Sort-Object -Unique)
            BypassRequired = @($grouped.Group | Where-Object { $_.BypassRequired }).Count -gt 0
        }
    }
    return $result
}

function Limit-Z2OCandidatePool {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates,
        [ValidateRange(1, 20)][int]$PerKind = 4
    )
    $result = @()
    foreach ($grouped in ($Candidates | Group-Object { "$($_.IpVersion)`t$($_.Kind)" })) {
        $result += @($grouped.Group | Sort-Object `
            @{ Expression = { if ($_.PSObject.Properties.Name -contains 'Priority') { $_.Priority } else { 10 } } }, `
            @{ Expression = { Get-Z2OProductionPenalty -Strategy $_.Strategy } }, Order | Select-Object -First $PerKind)
    }
    return $result
}

function Test-Z2OCandidateCoverage {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][int[]]$Versions
    )
    foreach ($version in $Versions) {
        foreach ($kind in @(Get-Z2ORequiredKinds -Group $Group)) {
            if (@($Candidates | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind }).Count -eq 0) {
                return $false
            }
        }
    }
    return $true
}

function Get-Z2OCoveredIpVersions {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][int[]]$Versions
    )
    return @($Versions | Where-Object {
        Test-Z2OCandidateCoverage -Candidates $Candidates -Group $Group -Versions @($_)
    })
}

function Select-Z2OValidatedCandidates {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Validated,
        [Parameter(Mandatory)]$Group,
        [int[]]$RequiredVersions = @(4)
    )
    $selected = @()
    foreach ($version in @($Candidates | Select-Object -ExpandProperty IpVersion -Unique | Sort-Object)) {
        $versionSelection = @()
        $missingKind = $null
        $requiredKinds = @(Get-Z2ORequiredKinds -Group $Group)
        foreach ($kind in @(Get-Z2OExpectedKinds -Group $Group)) {
            $order = @($Candidates | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind } |
                Sort-Object @{ Expression = { Get-Z2OProductionPenalty -Strategy $_.Strategy } }, Order)
            $validStrategies = @($Validated | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind } |
                Select-Object -ExpandProperty Strategy)
            $winner = $order | Where-Object { $validStrategies -contains $_.Strategy } | Select-Object -First 1
            if (-not $winner) {
                if ($requiredKinds -contains $kind) {
                    $missingKind = $kind
                    break
                }
                Write-Warning "Skipping optional $kind coverage for $($Group.id), IPv$version."
                continue
            }
            $versionSelection += $winner
        }
        if ($missingKind) {
            if ($RequiredVersions -contains [int]$version) {
                throw (New-Z2OSelectionFailure -Status 'no-strategy' `
                    -Message "No stable $missingKind strategy for $($Group.id), IPv$version.")
            }
            Write-Warning "Skipping optional IPv$version for $($Group.id): validation found no stable $missingKind strategy."
            continue
        }
        $selected += $versionSelection
    }
    foreach ($requiredVersion in $RequiredVersions) {
        if (@($selected | Where-Object IpVersion -eq $requiredVersion).Count -eq 0) {
            throw (New-Z2OSelectionFailure -Status 'no-strategy' `
                -Message "No stable strategy set for required IPv$requiredVersion coverage of $($Group.id).")
        }
    }
    return $selected
}

function New-Z2OValidationSuite {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][object[]]$Candidates
    )
    $testName = 'z2o-validation-' + [Guid]::NewGuid().ToString('N')
    $suite = Join-Path $InstallRoot "vendor\zapret2\blockcheck2.d\$testName"
    New-Item -ItemType Directory -Path $suite -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $InstallRoot 'vendor\zapret2\blockcheck2.d\custom\10-list.sh') -Destination $suite

    $tls = @($Candidates | Where-Object { $_.Kind -eq 'tls' -and $_.BypassRequired -and $_.Strategy } |
        Sort-Object Order | Select-Object -ExpandProperty Strategy -Unique)
    $quic = @($Candidates | Where-Object { $_.Kind -eq 'quic' -and $_.BypassRequired -and $_.Strategy } |
        Sort-Object Order | Select-Object -ExpandProperty Strategy -Unique)
    Set-Content -LiteralPath (Join-Path $suite 'list_http.txt') -Value @() -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $suite 'list_https_tls12.txt') -Value $tls -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $suite 'list_https_tls13.txt') -Value $tls -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $suite 'list_quic.txt') -Value $quic -Encoding ASCII
    return [pscustomobject]@{ Name = $testName; Path = $suite }
}

function Select-Z2OStableStrategies {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][object[]]$Candidates,
        [int[]]$RequiredVersions = @(4),
        [string]$RunRoot,
        [string]$BashPath
    )
    if (@($Candidates | Where-Object BypassRequired).Count -eq 0) {
        return @($Candidates)
    }
    $suite = New-Z2OValidationSuite -InstallRoot $InstallRoot -Candidates $Candidates
    try {
        $validationGroup = $Group
        $tlsCandidates = @($Candidates | Where-Object Kind -eq 'tls')
        if ($tlsCandidates.Count -gt 0 -and @($tlsCandidates | Where-Object { -not $_.Degraded }).Count -eq 0) {
            $validationGroup = [pscustomobject]@{
                id = $Group.id
                displayName = $Group.displayName
                probeDomains = @($Group.probeDomains)
                protocols = @($Group.protocols | Where-Object { $_ -ne 'https-tls12' })
            }
            Write-Warning "$($Group.id): no common TLS 1.2 candidate; validating a TLS 1.3-only degraded profile."
        }
        $run = Invoke-Z2OBlockcheckRun -InstallRoot $InstallRoot -Group $validationGroup -TestName $suite.Name `
            -ScanLevel force -Repeats 5 -MinimumSuccesses 3 -RunLabel "$($Group.id)-validation" `
            -MaxRunSeconds 900 -StallSeconds 120 -AllowPartialAtLimit `
            -RunRoot $RunRoot -BashPath $BashPath
        $validated = @(Get-Z2OCandidatesFromRun -Run $run -Group $validationGroup)
        return @(Select-Z2OValidatedCandidates -Candidates $Candidates -Validated $validated -Group $Group `
            -RequiredVersions $RequiredVersions)
    }
    finally {
        Remove-Item -LiteralPath $suite.Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-Z2OWordexpToken {
    param([Parameter(Mandatory)][string]$Value)
    $single = [string][char]39
    $double = [string][char]34
    $replacement = $single + $double + $single + $double + $single
    return $single + $Value.Replace($single, $replacement) + $single
}

function ConvertTo-Z2OConfigPath {
    param([Parameter(Mandatory)][string]$Path)
    return $Path.Replace('\', '/')
}

function Write-Z2OActiveConfig {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)][object[]]$Selections,
        [string]$PublishedInstallRoot
    )
    if (-not $PublishedInstallRoot) { $PublishedInstallRoot = $InstallRoot }
    $runtime = Join-Path $InstallRoot 'runtime'
    New-Item -ItemType Directory -Path $runtime -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $runtime 'writable') -Force | Out-Null
    Backup-Z2OActiveConfig -InstallRoot $InstallRoot

    $lines = New-Object System.Collections.Generic.List[string]
    $zapret = Join-Path $PublishedInstallRoot 'vendor\zapret2'
    $luaLib = ConvertTo-Z2OConfigPath (Join-Path $zapret 'lua\zapret-lib.lua')
    $luaAntidpi = ConvertTo-Z2OConfigPath (Join-Path $zapret 'lua\zapret-antidpi.lua')
    $discordMedia = ConvertTo-Z2OConfigPath (Join-Path $zapret 'windivert.filter\windivert_part.discord_media.txt')
    $stun = ConvertTo-Z2OConfigPath (Join-Path $zapret 'windivert.filter\windivert_part.stun.txt')
    $writable = ConvertTo-Z2OConfigPath (Join-Path $PublishedInstallRoot 'runtime\writable')

    $lines.Add((ConvertTo-Z2OWordexpToken "--writable=$writable"))
    $lines.Add((ConvertTo-Z2OWordexpToken "--lua-init=@$luaLib"))
    $lines.Add((ConvertTo-Z2OWordexpToken "--lua-init=@$luaAntidpi"))
    # v1.x support is explicitly IPv4-only. Restrict capture at the WinDivert
    # layer so dual-stack traffic can never fall through IPv4-only profiles.
    $lines.Add((ConvertTo-Z2OWordexpToken '--wf-l3=ipv4'))
    if (@($Selections | Where-Object {
        (-not ($_.PSObject.Properties.Name -contains 'BypassRequired') -or $_.BypassRequired) -and $_.Kind -eq 'tls'
    }).Count -gt 0) {
        $lines.Add((ConvertTo-Z2OWordexpToken '--wf-tcp-out=443'))
    }
    if (@($Selections | Where-Object {
        (-not ($_.PSObject.Properties.Name -contains 'BypassRequired') -or $_.BypassRequired) -and $_.Kind -eq 'quic'
    }).Count -gt 0) {
        $lines.Add((ConvertTo-Z2OWordexpToken '--wf-udp-out=443'))
    }
    $lines.Add((ConvertTo-Z2OWordexpToken "--wf-raw-part=@$discordMedia"))
    $lines.Add((ConvertTo-Z2OWordexpToken "--wf-raw-part=@$stun"))

    $profileIndex = 0
    foreach ($selection in ($Selections | Sort-Object GroupId, IpVersion, Kind)) {
        if (($selection.PSObject.Properties.Name -contains 'BypassRequired') -and -not $selection.BypassRequired) { continue }
        if ($profileIndex -gt 0) { $lines.Add((ConvertTo-Z2OWordexpToken '--new')) }
        $profileIndex++
        $group = @($Catalog.groups | Where-Object id -eq $selection.GroupId)[0]
        $hostlist = ConvertTo-Z2OConfigPath (Join-Path $PublishedInstallRoot ('config\' + $group.hostlist.Replace('/', '\')))
        $lines.Add((ConvertTo-Z2OWordexpToken ('--filter-l3=ipv{0}' -f $selection.IpVersion)))
        if ($selection.Kind -eq 'tls') {
            $lines.Add((ConvertTo-Z2OWordexpToken '--filter-tcp=443'))
            $lines.Add((ConvertTo-Z2OWordexpToken '--filter-l7=tls'))
        }
        else {
            $lines.Add((ConvertTo-Z2OWordexpToken '--filter-udp=443'))
            $lines.Add((ConvertTo-Z2OWordexpToken '--filter-l7=quic'))
        }
        $lines.Add((ConvertTo-Z2OWordexpToken "--hostlist=$hostlist"))
        $lines.Add($selection.Strategy)
    }

    if ($profileIndex -gt 0) { $lines.Add((ConvertTo-Z2OWordexpToken '--new')) }
    $lines.Add((ConvertTo-Z2OWordexpToken '--filter-l7=stun,discord'))
    $lines.Add((ConvertTo-Z2OWordexpToken '--payload=discord_ip_discovery,stun'))
    $lines.Add((ConvertTo-Z2OWordexpToken '--lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2'))

    $active = Join-Path $runtime 'active.conf'
    $lines | Set-Content -LiteralPath $active -Encoding ASCII
    return $active
}

function New-Z2OSelectionFailure {
    param(
        [Parameter(Mandatory)][ValidateSet('no-strategy', 'infra-failure')][string]$Status,
        [Parameter(Mandatory)][string]$Message
    )
    $exception = New-Object System.InvalidOperationException($Message)
    $exception.Data['Z2OStatus'] = $Status
    return $exception
}

function Get-Z2OFailureStatusFromRecords {
    param([AllowEmptyCollection()][object[]]$Records)
    if (@($Records | Where-Object { $_.Status -like 'infra-failure:*' }).Count -gt 0) { return 'infra-failure' }
    return 'no-strategy'
}

function Invoke-Z2OStrategySelectionCore {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)]$Catalog,
        [string]$RunRoot,
        [string]$BashPath
    )
    $selections = @()
    $groupOutcomes = @()
    foreach ($group in @($Catalog.groups)) {
        $groupRequired = -not ($group.PSObject.Properties.Name -contains 'required') -or [bool]$group.required
        try {
        # Start with upstream's short custom list. It contains the current
        # high-value TLS/QUIC candidates and keeps first-run latency bounded.
        # Missing coverage escalates to a time-bounded standard suite below.
        $discoverySuite = if ($group.PSObject.Properties.Name -contains 'strategySuite') { [string]$group.strategySuite } else { 'custom' }
        $discovery = Invoke-Z2OBlockcheckRun -InstallRoot $InstallRoot -Group $group -TestName $discoverySuite `
            -ScanLevel quick -Repeats 1 -RunLabel "$($group.id)-discovery" -MaxRunSeconds 300 -StallSeconds 120 `
            -AllowPartialAtLimit -RunRoot $RunRoot -BashPath $BashPath
        $candidates = @(Get-Z2OCandidatesFromRun -Run $discovery -Group $group)

        $scanVersions = @(4)
        $requiredVersions = @(4)
        if (-not (Test-Z2OCandidateCoverage -Candidates $candidates -Group $group -Versions $requiredVersions)) {
            Write-Warning "The short list did not cover $($group.id); running a bounded standard fallback (not exhaustive force)."
            $fallback = Invoke-Z2OBlockcheckRun -InstallRoot $InstallRoot -Group $group -TestName 'standard' `
                -ScanLevel standard -Repeats 1 -RunLabel "$($group.id)-fallback" -MaxRunSeconds 400 -StallSeconds 120 `
                -AllowPartialAtLimit -RunRoot $RunRoot -BashPath $BashPath

            $quickCommon = @($candidates)
            $fallbackCommon = @(Get-Z2OCandidatesFromRun -Run $fallback -Group $group)
            $quickPool = @(Get-Z2ODiscoveryPoolFromRun -Run $discovery -Group $group)
            $fallbackPool = @(Get-Z2ODiscoveryPoolFromRun -Run $fallback -Group $group)
            foreach ($candidate in $quickCommon) { $candidate | Add-Member Priority 0 -Force }
            foreach ($candidate in $fallbackCommon) { $candidate | Add-Member Priority 1 -Force }
            foreach ($candidate in $fallbackPool) { $candidate | Add-Member Priority 2 -Force }
            foreach ($candidate in $quickPool) { $candidate | Add-Member Priority 3 -Force }
            $candidates = @(Limit-Z2OCandidatePool -Candidates @(
                Merge-Z2OCandidatePools -Candidates @($quickCommon + $fallbackCommon + $fallbackPool + $quickPool)
            ) -PerKind 2)

            if (-not (Test-Z2OCandidateCoverage -Candidates $candidates -Group $group -Versions $requiredVersions)) {
                $failureStatus = Get-Z2OFailureStatusFromRecords -Records @($discovery.Records + $fallback.Records)
                throw (New-Z2OSelectionFailure -Status $failureStatus `
                    -Message "No bounded candidate pool covers required IPv4/TLS for $($group.id). Logs: $($fallback.Directory)")
            }
        }

        $coveredVersions = @(Get-Z2OCoveredIpVersions -Candidates $candidates -Group $group -Versions $scanVersions)
        $candidates = @($candidates | Where-Object { $coveredVersions -contains [int]$_.IpVersion })

        # Validation cost is proportional to candidates x domains x protocols x
        # repeats. Never pass an unbounded set even when the quick suite found many.
        $candidates = @(Limit-Z2OCandidatePool -Candidates $candidates -PerKind 2)

        $stable = @(Select-Z2OStableStrategies -InstallRoot $InstallRoot -Group $group -Candidates $candidates `
            -RequiredVersions $requiredVersions -RunRoot $RunRoot -BashPath $BashPath)
        foreach ($item in $stable) {
            $selections += [pscustomobject]@{
                GroupId = $group.id
                Kind = $item.Kind
                IpVersion = $item.IpVersion
                Strategy = $item.Strategy
                DiscoveryOrder = $item.Order
                Degraded = [bool]$item.Degraded
                ValidatedProtocols = @($item.ValidatedProtocols)
                BypassRequired = [bool]$item.BypassRequired
            }
        }
        $missingOptionalKinds = @(Get-Z2OExpectedKinds -Group $group | Where-Object {
            $kind = $_
            @(Get-Z2ORequiredKinds -Group $group) -notcontains $kind -and
                @($stable | Where-Object Kind -eq $kind).Count -eq 0
        })
        $groupOutcomes += [pscustomobject]@{
            GroupId = $group.id
            Required = $groupRequired
            Status = if (@($stable | Where-Object BypassRequired).Count -eq 0) { 'not-blocked' }
                elseif ($missingOptionalKinds.Count -gt 0 -or @($stable | Where-Object Degraded).Count -gt 0) { 'degraded' }
                else { 'selected' }
            MissingOptionalKinds = $missingOptionalKinds
            Error = $null
        }
        }
        catch {
            $failureStatus = if ($_.Exception.Data.Contains('Z2OStatus')) {
                [string]$_.Exception.Data['Z2OStatus']
            } else { 'infra-failure' }
            if ($groupRequired) { throw }
            Write-Warning "$($group.id) is optional and was skipped ($failureStatus): $($_.Exception.Message)"
            $groupOutcomes += [pscustomobject]@{
                GroupId = $group.id
                Required = $false
                Status = $failureStatus
                MissingOptionalKinds = @()
                Error = $_.Exception.Message
            }
            continue
        }
    }
    $requiredOutcomes = @($groupOutcomes | Where-Object Required)
    if ($requiredOutcomes.Count -eq 0) {
        throw 'The service catalog must contain at least one required group.'
    }
    return [pscustomobject]@{ Selections = @($selections); Groups = @($groupOutcomes) }
}
