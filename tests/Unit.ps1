$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$module = Join-Path $root 'launcher\Zapret2OneClick.psm1'
Import-Module $module -Force

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

$temp = Join-Path $env:TEMP ('z2o-unit-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $report = Join-Path $temp 'machine.tsv'
    @(
        "1`talpha.test`tcurl_test_https_tls12`t4`tok`t'--payload=tls_client_hello' '--out-range=<s1'",
        "2`talpha.test`tcurl_test_https_tls13`t4`tok`t'--payload=tls_client_hello' '--out-range=<s1'",
        "3`tbeta.test`tcurl_test_https_tls12`t4`tnot-blocked`t",
        "4`tbeta.test`tcurl_test_https_tls13`t4`tok`t'--payload=tls_client_hello' '--out-range=<s1'"
    ) | Set-Content -LiteralPath $report -Encoding ASCII
    $records = @(Read-Z2OMachineReport -Path $report)
    Assert-True ((Get-Z2OFailureStatusFromRecords -Records @(
        [pscustomobject]@{ Status = 'infra-failure:6' }
    )) -eq 'infra-failure') 'typed infrastructure failures must remain distinct from no-strategy (B8)'
    $truncatedReport = Join-Path $temp 'truncated-machine.tsv'
    [IO.File]::WriteAllText($truncatedReport, "1`talpha.test`tcurl_test_https_tls13`t4`tok`t'--strategy=x'", `
        [Text.Encoding]::ASCII)
    $truncatedFailed = $false
    try { $null = @(Read-Z2OMachineReport -Path $truncatedReport) }
    catch { $truncatedFailed = $_.Exception.Message -match 'Truncated blockcheck machine report' }
    Assert-True $truncatedFailed 'a torn machine-report record must fail closed instead of being salvaged (B2/B8)'
    $group = [pscustomobject]@{
        id = 'alpha'
        probeDomains = @('alpha.test', 'beta.test')
        protocols = @('https-tls12', 'https-tls13')
    }
    $common = @(Get-Z2OCommonCandidates -Records $records -Group $group -Kind tls -IpVersion 4)
    Assert-True ($common.Count -eq 1) 'TLS intersection must contain one strategy'
    Assert-True ($common[0].Strategy -like "*--out-range=<s1*") 'strategy quoting must be preserved'

    $tls13OnlyReport = Join-Path $temp 'tls13-only.tsv'
    @(
        "1`talpha.test`tcurl_test_https_tls13`t4`tok`t'--payload=tls_client_hello'",
        "2`tbeta.test`tcurl_test_https_tls13`t4`tok`t'--payload=tls_client_hello'"
    ) | Set-Content -LiteralPath $tls13OnlyReport -Encoding ASCII
    $degradedRun = [pscustomobject]@{ Records = @(Read-Z2OMachineReport -Path $tls13OnlyReport) }
    $degraded = @(Get-Z2OCandidatesFromRun -Run $degradedRun -Group $group)
    Assert-True ($degraded.Count -eq 1 -and $degraded[0].Degraded) 'TLS 1.3-only discovery must produce an explicit degraded candidate'

    $poolReport = Join-Path $temp 'pool.tsv'
    @(
        "1`talpha.test`tcurl_test_https_tls12`t4`tok`t'--strategy=a'",
        "2`tbeta.test`tcurl_test_https_tls13`t4`tok`t'--strategy=b'",
        "3`talpha.test`tcurl_test_https_tls12`t4`tok`t'--strategy=c'",
        "4`talpha.test`tcurl_test_https_tls13`t4`tok`t'--strategy=c'"
    ) | Set-Content -LiteralPath $poolReport -Encoding ASCII
    $poolRun = [pscustomobject]@{ Records = @(Read-Z2OMachineReport -Path $poolReport) }
    $pool = @(Get-Z2ODiscoveryPoolFromRun -Run $poolRun -Group $group)
    Assert-True ($pool.Count -eq 3) 'bounded fallback must retain the union of discovered strategies for targeted validation'
    Assert-True (@($pool | Where-Object { $_.Strategy -eq "'--strategy=b'" -and $_.Degraded }).Count -eq 1) `
        'TLS 1.3-only pool entries must remain explicitly degraded'
    foreach ($candidate in $pool) { $candidate | Add-Member Priority 2 -Force }
    $mergedPool = @(Merge-Z2OCandidatePools -Candidates @($pool + $degraded))
    $limitedPool = @(Limit-Z2OCandidatePool -Candidates $mergedPool -PerKind 2)
    Assert-True ($limitedPool.Count -eq 2) 'candidate validation pool must be bounded per protocol kind'
    Assert-True (Test-Z2OCandidateCoverage -Candidates $limitedPool -Group $group -Versions @(4)) `
        'bounded TLS pool must report protocol-kind coverage'

    $ipv4Candidate = [pscustomobject]@{
        Kind = 'tls'; IpVersion = 4; Strategy = "'--strategy=ipv4'"; Order = 1; Degraded = $false
        BypassRequired = $true; ValidatedProtocols = @('https-tls12', 'https-tls13')
    }
    $requiredFailed = $false
    try {
        $null = Select-Z2OValidatedCandidates -Candidates @($ipv4Candidate) -Validated @() `
            -Group $group -RequiredVersions @(4)
    }
    catch { $requiredFailed = $true }
    Assert-True $requiredFailed 'missing required IPv4 validation must still fail closed'

    $quicGroup = [pscustomobject]@{
        id = 'quic-optional'; probeDomains = @('alpha.test')
        protocols = @('https-tls12', 'https-tls13', 'quic'); requiredKinds = @('tls')
    }
    Assert-True (Test-Z2OCandidateCoverage -Candidates @($ipv4Candidate) -Group $quicGroup -Versions @(4)) `
        'missing QUIC must degrade to browser TLS instead of rejecting installation (B7)'

    Assert-True ((Get-Z2OProductionPenalty -Strategy "'--lua-desync=oob:urp=midsld'") -gt
        (Get-Z2OProductionPenalty -Strategy "'--lua-desync=fake:blob=fake_default_tls'")) 'OOB must rank behind a stable payload strategy'

    $progressLog = Join-Path $temp 'progress.log'
    @(
        '- curl_test_https_tls12 ipv4 alpha.test : strategy-a',
        '!!!!! AVAILABLE !!!!!',
        '- curl_test_https_tls13 ipv4 alpha.test : strategy-b',
        'UNAVAILABLE code=28'
    ) | Set-Content -LiteralPath $progressLog -Encoding ASCII
    $progress = Get-Z2OBlockcheckProgress -Path $progressLog
    Assert-True ($progress.Tests -eq 2 -and $progress.Successes -eq 1 -and $progress.Length -gt 0) `
        'heartbeat progress must report real tests and successes from the live log'

    $cygwinLog = Join-Path $temp 'cygwin.err.log'
    Set-Content -LiteralPath $cygwinLog `
        -Value '0 [main] curl 123 child_copy: cygheap read copy failed, Win32 error 299' -Encoding ASCII
    Assert-True (Test-Z2OCygwinFailureLog -Path $cygwinLog) `
        'Cygwin child_copy diagnostics must remain observable'

    $winwsPath = Join-Path $root 'vendor\zapret2\nfq2\winws2.exe'
    $winwsBytes = [IO.File]::ReadAllBytes($winwsPath)
    $peOffset = [BitConverter]::ToInt32($winwsBytes, 0x3c)
    $dllCharacteristics = [BitConverter]::ToUInt16($winwsBytes, $peOffset + 24 + 70)
    Assert-True (($dllCharacteristics -band 0x60) -eq 0) `
        'derived winws2 must clear DYNAMIC_BASE and HIGH_ENTROPY_VA (B4)'
    $serviceWinws = Join-Path $root 'vendor\zapret2\service\winws2.exe'
    Assert-True ((Get-Z2OSha256 -Path $serviceWinws) -eq (Get-Z2OSha256 -Path $winwsPath)) `
        'blockcheck and service paths must use the same PE-fixed winws2 bytes'

    $blockcheckRunBody = (Get-Command Invoke-Z2OBlockcheckRun).ScriptBlock.ToString()
    Assert-True ($blockcheckRunBody -match 'OverallWallSeconds' -and $blockcheckRunBody -match 'AttemptWallSeconds') `
        'soft lease, per-attempt wall and overall wall clocks must be distinct (B3)'
    Assert-True ($blockcheckRunBody -match 'Remove-Item -LiteralPath \$stdoutPath, \$stderrPath, \$machinePath') `
        'retry must start from clean live files after archiving the prior attempt'
    Assert-True ((Get-Command Select-Z2OStableStrategies).ScriptBlock.ToString() -match 'AllowPartialAtLimit') `
        'complete validation records must survive irrelevant Cygwin child stderr (B2)'
    $customRunner = Get-Content -LiteralPath (Join-Path $root 'vendor\zapret2\blockcheck2.d\custom\10-list.sh') -Raw
    Assert-True ($customRunner -match 'QUICK_MAX_SUCCESSES:-2') `
        'quick discovery must retain up to two successful candidates instead of collapsing to one (H1)'
    $blockcheckSource = Get-Content -LiteralPath (Join-Path $root 'vendor\zapret2\blockcheck2.sh') -Raw
    Assert-True ($blockcheckSource -match 'MIN_SUCCESSES' -and $blockcheckSource -match 'machine_report_append.*not-blocked') `
        'blockcheck must support k-of-n validation and typed probe outcomes (H1/B8)'

    # Exercise the actual multi-group selection coordinator. Only the expensive
    # process/network seam and validation runner are replaced; B1 control flow,
    # candidate construction, fallback and outcome taxonomy remain real.
    $z2oModule = Get-Module | Where-Object { $_.Path -eq $module } | Select-Object -First 1
    $originalBlockcheck = & $z2oModule { (Get-Item Function:Invoke-Z2OBlockcheckRun).ScriptBlock }
    $originalStable = & $z2oModule { (Get-Item Function:Select-Z2OStableStrategies).ScriptBlock }
    $blockcheckStub = {
        param($InstallRoot, $Group, $TestName, $ScanLevel, $Repeats, $RunLabel,
            $MaxRunSeconds, $StallSeconds, [switch]$AllowPartialAtLimit, $RunRoot, $BashPath)
        $tests = @('curl_test_https_tls12', 'curl_test_https_tls13')
        $records = @()
        $sequence = 0
        foreach ($domain in @($Group.probeDomains)) {
            foreach ($test in $tests) {
                $sequence++
                $records += if ($Group.id -eq 'youtube') {
                    [pscustomobject]@{
                        Sequence = $sequence; Domain = $domain; Test = $test; IpVersion = 4
                        Status = 'ok'; Strategy = "'--strategy=youtube'"
                    }
                } else {
                    [pscustomobject]@{
                        Sequence = $sequence; Domain = $domain; Test = $test; IpVersion = 4
                        Status = 'no-strategy'; Strategy = ''
                    }
                }
            }
        }
        return [pscustomobject]@{ Records = $records; Directory = "stub-$($Group.id)-$RunLabel"; Status = 'completed' }
    }
    $stableStub = {
        param($InstallRoot, $Group, $Candidates, $RequiredVersions, $RunRoot, $BashPath)
        return @($Candidates)
    }
    & $z2oModule {
        param($RunStub, $StableStub)
        Set-Item Function:Invoke-Z2OBlockcheckRun $RunStub
        Set-Item Function:Select-Z2OStableStrategies $StableStub
    } $blockcheckStub $stableStub
    try {
        $multiCatalog = [pscustomobject]@{ groups = @(
            [pscustomobject]@{
                id = 'youtube'; displayName = 'YouTube'; required = $true; requiredKinds = @('tls')
                probeDomains = @('youtube.test'); protocols = @('https-tls12', 'https-tls13')
            },
            [pscustomobject]@{
                id = 'discord-web'; displayName = 'Discord'; required = $false; requiredKinds = @('tls')
                probeDomains = @('discord.test'); protocols = @('https-tls12', 'https-tls13')
            }
        ) }
        $multiResult = Invoke-Z2OStrategySelectionCore -InstallRoot $root -Catalog $multiCatalog
        Assert-True (@($multiResult.Selections | Where-Object GroupId -eq 'youtube').Count -eq 1) `
            'required YouTube selection must survive optional Discord 175/0 semantics (B1)'
        Assert-True (@($multiResult.Groups | Where-Object {
            $_.GroupId -eq 'discord-web' -and $_.Status -eq 'no-strategy'
        }).Count -eq 1) 'optional Discord no-strategy must be explicit, not an all-or-nothing throw (B1/B8)'

        $multiCatalog.groups[1].required = $true
        $requiredDiscordFailed = $false
        try { $null = Invoke-Z2OStrategySelectionCore -InstallRoot $root -Catalog $multiCatalog }
        catch { $requiredDiscordFailed = $true }
        Assert-True $requiredDiscordFailed 'a required group with no strategy must still fail closed'
    }
    finally {
        & $z2oModule {
            param($RunOriginal, $StableOriginal)
            Set-Item Function:Invoke-Z2OBlockcheckRun $RunOriginal
            Set-Item Function:Select-Z2OStableStrategies $StableOriginal
        } $originalBlockcheck $originalStable
    }

    $preflightInput = Join-Path $temp 'preflight-input.conf'
    @("'--wf-tcp-out=443'", "'--wf-udp-out=443'", "'--wf-raw-part=@filter.txt'", "'--filter-l7=tls'") |
        Set-Content -LiteralPath $preflightInput -Encoding ASCII
    $preflightLines = @(Get-Z2OPreflightConfigLines -ConfigPath $preflightInput)
    Assert-True ($preflightLines -contains "'--wf-tcp-out=65535'") `
        'preflight must avoid the live TCP capture filter'
    Assert-True ($preflightLines -contains "'--wf-udp-out=65535'") `
        'preflight must avoid the live UDP capture filter'
    Assert-True ($preflightLines -contains "'--wf-raw-part=@filter.txt'") `
        'preflight must still validate raw filter parts'

    $quoted = ConvertTo-Z2OWordexpToken -Value "a'b"
    Assert-True ($quoted -eq "'a'`"'`"'b'") 'single quote must be wordexp-safe'

    $install = Join-Path $temp 'install'
    Initialize-Z2OCygwinRuntime -InstallRoot $install
    Assert-True (Test-Path -LiteralPath (Join-Path $install 'vendor\cygwin\tmp') -PathType Container) `
        'Cygwin /tmp must be recreated when an archive omitted the empty directory'
    New-Item -ItemType Directory -Path (Join-Path $install 'config\hostlists') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $install 'vendor\zapret2\lua') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $install 'vendor\zapret2\windivert.filter') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $install 'config\hostlists\alpha.txt') -Value 'alpha.test' -Encoding ASCII
    $catalog = [pscustomobject]@{
        groups = @([pscustomobject]@{ id = 'alpha'; hostlist = 'hostlists/alpha.txt' })
    }
    $selection = @([pscustomobject]@{
        GroupId = 'alpha'; Kind = 'tls'; IpVersion = 4
        Strategy = "'--payload=tls_client_hello' '--lua-desync=multisplit:pos=1'"
        BypassRequired = $true
    })
    New-Item -ItemType Directory -Path (Join-Path $install 'runtime') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $install 'runtime\active.conf') -Value 'old-config' -Encoding ASCII
    $config = Write-Z2OActiveConfig -InstallRoot $install -Catalog $catalog -Selections $selection
    $content = Get-Content -LiteralPath $config -Raw
    Assert-True ($content -match '--filter-l3=ipv4') 'config must contain L3 profile filter'
    Assert-True (($content -split "`r?`n") -contains "'--wf-l3=ipv4'") `
        'capture must be explicitly IPv4-only (H2)'
    Assert-True ($content -match '--hostlist=') 'config must contain hostlist'
    Assert-True ($content -match '--filter-l7=stun,discord') 'config must contain curated Discord UDP profile'
    Assert-True ((Get-Content -LiteralPath (Join-Path $install 'runtime\previous.conf') -Raw) -match 'old-config') 'previous config must be preserved for rollback'

    Assert-True ((Get-Z2OWinDivertOwnership -InstallRoot $install) -eq 'unknown') 'missing driver ownership marker must fail safe'
    Set-Z2OWinDivertOwnership -InstallRoot $install -Ownership preexisting
    Assert-True ((Get-Z2OWinDivertOwnership -InstallRoot $install) -eq 'preexisting') 'preexisting driver ownership must be recorded'
    Set-Z2OWinDivertOwnership -InstallRoot $install -Ownership owned
    Assert-True ((Get-Z2OWinDivertOwnership -InstallRoot $install) -eq 'owned') 'owned driver state must be recorded'
    $nativeDriver = ConvertFrom-Z2ODriverServicePath -PathName '\??\C:\ProgramData\zapret2-oneclick\WinDivert64.sys'
    Assert-True ($nativeDriver -eq 'C:\ProgramData\zapret2-oneclick\WinDivert64.sys') `
        'NT driver paths must normalize before physical InstallRoot ownership checks'
    Assert-True (Test-Z2OPathUnderRoot -Path $nativeDriver -Root 'C:\ProgramData\zapret2-oneclick') `
        'a loaded WinDivert.sys under InstallRoot must count as physically owned'

    $scratchA = Join-Path $temp 'isolated-a'
    $scratchB = Join-Path $temp 'isolated-b'
    Assert-True ((Get-Z2OServiceName -InstallRoot $scratchA) -ne 'zapret2-oneclick') `
        'custom InstallRoot must derive a non-production service name (H3)'
    Assert-True ((Get-Z2OServiceName -InstallRoot $scratchA) -ne (Get-Z2OServiceName -InstallRoot $scratchB)) `
        'distinct custom roots must derive distinct service names'
    Assert-True ((Get-Z2OInstallerLockPath -InstallRoot $scratchA) -ne
        (Get-Z2OInstallerLockPath -InstallRoot (Get-Z2ODefaultInstallRoot))) `
        'custom InstallRoot must not share the production installer lock (H3)'
    foreach ($functionName in @('Stop-Z2OExistingInstallerProcesses', 'Stop-Z2OInstallProcesses')) {
        Assert-True ((Get-Command $functionName).ScriptBlock.ToString() -notmatch 'taskkill') `
            "$functionName must not let native stderr abort rollback (B6)"
    }

    $serviceAssertionBody = (Get-Command Assert-Z2OServiceRunning).ScriptBlock.ToString()
    Assert-True ($serviceAssertionBody -notmatch 'Invoke-Z2OSc') `
        'service state checks must not parse localized sc.exe output'
    Assert-Z2OServiceRunning -Name 'EventLog' -TimeoutSeconds 2
    $missingServiceFailed = $false
    try { Assert-Z2OServiceRunning -Name ('z2o-unit-' + [Guid]::NewGuid().ToString('N')) -TimeoutSeconds 1 }
    catch {
        $missingServiceFailed = $_.Exception.Message -match 'service not found'
    }
    Assert-True $missingServiceFailed 'a missing service must report locale-independent SCM diagnostics'

    $payloadSource = Join-Path $temp 'payload-source'
    $payloadInstall = Join-Path $temp 'payload-install'
    New-Item -ItemType Directory -Path (Join-Path $payloadSource 'config'),(Join-Path $payloadSource 'checksums'),(Join-Path $payloadInstall 'runtime') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $payloadSource 'config\new.txt') -Value 'new' -Encoding ASCII
    $payloadHash = Get-Z2OSha256 -Path (Join-Path $payloadSource 'config\new.txt')
    Set-Content -LiteralPath (Join-Path $payloadSource 'checksums\vendor.sha256') `
        -Value ("{0}  config/new.txt" -f $payloadHash) -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $payloadInstall 'runtime\keep.txt') -Value 'keep' -Encoding ASCII
    Install-Z2OPayload -SourceRoot $payloadSource -InstallRoot $payloadInstall
    Assert-True (Test-Path -LiteralPath (Join-Path $payloadInstall 'config\new.txt')) `
        'payload replacement must publish the new tree'
    Assert-True (Test-Path -LiteralPath (Join-Path $payloadInstall 'runtime\keep.txt')) `
        'payload replacement must preserve runtime state'
    Assert-True (@(Get-ChildItem -LiteralPath $temp -Directory -Filter 'payload-install.staging.*').Count -eq 0) `
        'payload staging must remain a cleaned sibling, never a nested install'

    $transactionInstall = Join-Path $temp 'transaction-install'
    $transactionStage = Join-Path $temp 'transaction-stage'
    New-Item -ItemType Directory -Path (Join-Path $transactionInstall 'runtime'),(Join-Path $transactionStage 'runtime') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $transactionInstall 'old.txt') -Value old -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $transactionStage 'new.txt') -Value new -Encoding ASCII
    $persistentRun = Join-Path (Get-Z2ORunRoot -InstallRoot $transactionInstall) 'failure-test\blockcheck.log'
    New-Item -ItemType Directory -Path (Split-Path -Parent $persistentRun) -Force | Out-Null
    Set-Content -LiteralPath $persistentRun -Value 'diagnostic survives rollback' -Encoding ASCII
    $snapshot = [pscustomobject]@{ WasPresent = $false; WasRunning = $false; HadWorkingConfig = $false }
    $transaction = New-Z2OUpgradeTransaction -InstallRoot $transactionInstall -StagedRoot $transactionStage `
        -ServiceSnapshot $snapshot
    Assert-True (Test-Path -LiteralPath (Join-Path $transactionInstall 'new.txt')) `
        'transaction must publish the staged payload'
    Assert-True (Test-Path -LiteralPath ([string]$transaction.State.backupRoot)) `
        'transaction must retain the old payload until commit'
    Restore-Z2OUpgradeTransaction -Transaction $transaction -SkipServiceActions
    Assert-True (Test-Path -LiteralPath (Join-Path $transactionInstall 'old.txt')) `
        'transaction rollback must restore the old payload'
    Assert-True (-not (Test-Path -LiteralPath $transaction.StatePath)) `
        'transaction rollback must remove its durable journal'
    Assert-True (Test-Path -LiteralPath $persistentRun -PathType Leaf) `
        'blockcheck diagnostics in the sibling .logs tree must survive transaction rollback'

    $cleanInstall = Join-Path $temp 'clean-transaction-install'
    $cleanStage = Join-Path $temp 'clean-transaction-stage'
    New-Item -ItemType Directory -Path $cleanStage -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $cleanStage 'new.txt') -Value new -Encoding ASCII
    $cleanSnapshot = [pscustomobject]@{
        WasPresent = $false; WasRunning = $false; HadWorkingConfig = $false
        ServiceName = (Get-Z2OServiceName -InstallRoot $cleanInstall)
    }
    $cleanTransaction = New-Z2OUpgradeTransaction -InstallRoot $cleanInstall -StagedRoot $cleanStage `
        -ServiceSnapshot $cleanSnapshot
    Restore-Z2OUpgradeTransaction -Transaction $cleanTransaction -SkipServiceActions
    Assert-True (-not (Test-Path -LiteralPath $cleanInstall)) `
        'failed clean install rollback must remove the published tree instead of pretending to restore it (B5)'

    & (Join-Path $root 'tests\PublicTextGate.ps1')

    Write-Host 'All unit tests passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
