$ErrorActionPreference = 'Stop'
$module = Join-Path (Split-Path -Parent $PSScriptRoot) 'launcher\Zapret2OneClick.psm1'
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
        "1`talpha.test`tcurl_test_https_tls12`t4`t'--payload=tls_client_hello' '--out-range=<s1'",
        "2`talpha.test`tcurl_test_https_tls13`t4`t'--payload=tls_client_hello' '--out-range=<s1'",
        "3`tbeta.test`tcurl_test_https_tls12`t4`t'--payload=tls_client_hello' '--out-range=<s1'",
        "4`tbeta.test`tcurl_test_https_tls13`t4`t'--payload=tls_client_hello' '--out-range=<s1'"
    ) | Set-Content -LiteralPath $report -Encoding ASCII
    $records = @(Read-Z2OMachineReport -Path $report)
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
        "1`talpha.test`tcurl_test_https_tls13`t4`t'--payload=tls_client_hello'",
        "2`tbeta.test`tcurl_test_https_tls13`t4`t'--payload=tls_client_hello'"
    ) | Set-Content -LiteralPath $tls13OnlyReport -Encoding ASCII
    $degradedRun = [pscustomobject]@{ Records = @(Read-Z2OMachineReport -Path $tls13OnlyReport) }
    $degraded = @(Get-Z2OCandidatesFromRun -Run $degradedRun -Group $group)
    Assert-True ($degraded.Count -eq 1 -and $degraded[0].Degraded) 'TLS 1.3-only discovery must produce an explicit degraded candidate'

    $poolReport = Join-Path $temp 'pool.tsv'
    @(
        "1`talpha.test`tcurl_test_https_tls12`t4`t'--strategy=a'",
        "2`tbeta.test`tcurl_test_https_tls13`t4`t'--strategy=b'",
        "3`talpha.test`tcurl_test_https_tls12`t4`t'--strategy=c'",
        "4`talpha.test`tcurl_test_https_tls13`t4`t'--strategy=c'"
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
    }
    $ipv6Candidate = [pscustomobject]@{
        Kind = 'tls'; IpVersion = 6; Strategy = "'--strategy=ipv6'"; Order = 2; Degraded = $false
    }
    $covered = @(Get-Z2OCoveredIpVersions -Candidates @($ipv4Candidate) -Group $group -Versions @(4, 6))
    Assert-True ($covered.Count -eq 1 -and $covered[0] -eq 4) `
        'IPv4 coverage must remain usable when optional IPv6 has no candidates'
    $ipv4Only = @(Select-Z2OValidatedCandidates -Candidates @($ipv4Candidate, $ipv6Candidate) `
        -Validated @($ipv4Candidate) -Group $group -RequiredVersions @(4))
    Assert-True ($ipv4Only.Count -eq 1 -and $ipv4Only[0].IpVersion -eq 4) `
        'failed optional IPv6 validation must not reject stable IPv4'
    $dualStack = @(Select-Z2OValidatedCandidates -Candidates @($ipv4Candidate, $ipv6Candidate) `
        -Validated @($ipv4Candidate, $ipv6Candidate) -Group $group -RequiredVersions @(4))
    Assert-True ($dualStack.Count -eq 2) 'working IPv6 must remain selected alongside IPv4'
    $requiredFailed = $false
    try {
        $null = Select-Z2OValidatedCandidates -Candidates @($ipv4Candidate) -Validated @() `
            -Group $group -RequiredVersions @(4)
    }
    catch { $requiredFailed = $true }
    Assert-True $requiredFailed 'missing required IPv4 validation must still fail closed'

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
        'Cygwin child_copy error 299 must invalidate an attempt'

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
    })
    New-Item -ItemType Directory -Path (Join-Path $install 'runtime') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $install 'runtime\active.conf') -Value 'old-config' -Encoding ASCII
    $config = Write-Z2OActiveConfig -InstallRoot $install -Catalog $catalog -Selections $selection
    $content = Get-Content -LiteralPath $config -Raw
    Assert-True ($content -match '--filter-l3=ipv4') 'config must contain L3 profile filter'
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

    Write-Host 'All unit tests passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
