$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$module = Join-Path $root 'launcher\Zapret2OneClick.psm1'
Import-Module $module -Force

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Wait-ProcessGone {
    param([int]$Id, [int]$TimeoutSeconds = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (-not (Get-Process -Id $Id -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    return $false
}

$temp = Join-Path $env:TEMP ('z2o-watchdog-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $stdout = Join-Path $temp 'stall.log'
    $stderr = Join-Path $temp 'stall.err.log'
    $childPidPath = Join-Path $temp 'child.pid'
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    $stallScript = Join-Path $temp 'stall.ps1'
    @"
`$child = Start-Process -FilePath ping.exe -ArgumentList @('-t', '127.0.0.1') -PassThru
Set-Content -LiteralPath '$childPidPath' -Value `$child.Id -Encoding ASCII
Start-Sleep -Seconds 30
"@ | Set-Content -LiteralPath $stallScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $stallScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-stall-test' -MaxRunSeconds 10 -StallSeconds 2 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'stall') 'watchdog must classify an idle process as stalled'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    $childId = [int](Get-Content -LiteralPath $childPidPath -Raw)
    Assert-True (Wait-ProcessGone -Id $process.Id) 'watchdog must stop the parent process'
    Assert-True (Wait-ProcessGone -Id $childId) 'watchdog must stop the entire child process tree'

    $stdout = Join-Path $temp 'cygwin.log'
    $stderr = Join-Path $temp 'cygwin.err.log'
    $partialMachine = Join-Path $temp 'cygwin-partial.tsv'
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    Set-Content -LiteralPath $partialMachine `
        -Value "1`tpartial.test`tcurl_test_https_tls13`t4`t'--partial-result=must-not-be-used'" -Encoding ASCII
    $cygwinScript = Join-Path $temp 'cygwin.ps1'
    @"
Set-Content -LiteralPath '$stderr' -Value '0 [main] curl 123 child_copy: cygheap read copy failed, Win32 error 299' -Encoding ASCII
for (`$i = 0; `$i -lt 8; `$i++) {
    Add-Content -LiteralPath '$stdout' -Value "- curl_test_https_tls13 child `$i"
    Start-Sleep -Milliseconds 200
}
"@ | Set-Content -LiteralPath $cygwinScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $cygwinScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-cygwin-test' -MaxRunSeconds 10 -StallSeconds 8 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'completed') `
            'curl/winws2 child_copy stderr must not abort a live successful bash root (B2)'
        Assert-True ($outcome.CygwinFailures -eq 1) 'child failure must remain visible as diagnostics'
        Assert-True (@(Read-Z2OMachineReport -Path $partialMachine).Count -eq 1) `
            'failure injection must contain a tempting partial machine result'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    Assert-True (Wait-ProcessGone -Id $process.Id) 'child-warning attempt must finish cleanly'

    # H4/B3: invoke the real retry coordinator through its exact Cygwin bash
    # seam. Attempt 1 crosses and renews the soft lease, then its bash exits
    # after a child_copy diagnostic. Attempt 2 must actually start with a fresh
    # bounded lease and return a complete machine record.
    $cygpath = Join-Path $root 'vendor\cygwin\bin\cygpath.exe'
    $bash = Join-Path $root 'vendor\cygwin\bin\bash.exe'

    # H1: exercise the exact patched shell functions, not a PowerShell model.
    # Quick discovery must retain two successes, and force validation must use
    # the configured k-of-n threshold rather than requiring 5/5.
    $h1List = Join-Path $temp 'h1-list.txt'
    @('--candidate=one', '--candidate=two', '--candidate=three') |
        Set-Content -LiteralPath $h1List -Encoding ASCII
    $h1Script = Join-Path $temp 'h1-blockcheck-contract.sh'
    $customCyg = (& $cygpath -u -a (Join-Path $root 'vendor\zapret2\blockcheck2.d\custom\10-list.sh')).Trim()
    $blockcheckCyg = (& $cygpath -u -a (Join-Path $root 'vendor\zapret2\blockcheck2.sh')).Trim()
    $listCyg = (& $cygpath -u -a $h1List).Trim()
    $h1Text = @'
#!/bin/bash
set -e
. '__CUSTOM__'
calls=0
pktws_curl_test_update() { calls=$((calls+1)); return 0; }
SCANLEVEL=quick
QUICK_MAX_SUCCESSES=2
check_list mock example '__LIST__'
[ "$calls" = 2 ] || { echo "quick calls=$calls" >&2; exit 21; }

sed -n '/^curl_test()$/,/^ws_curl_test()$/{ /^ws_curl_test()$/d; p; }' '__BLOCKCHECK__' >curl-test-function.sh
. ./curl-test-function.sh
attempt=0
mock_curl() {
  attempt=$((attempt+1))
  case "$attempt" in 1|2|4) return 0 ;; *) return 28 ;; esac
}
PARALLEL=0
SCANLEVEL=force
REPEATS=5
MIN_SUCCESSES=3
IPV=4
curl_test mock_curl example.test >/dev/null
[ "$attempt" = 5 ] || { echo "k-of-n attempts=$attempt" >&2; exit 22; }
attempt=0
MIN_SUCCESSES=4
if curl_test mock_curl example.test >/dev/null; then
  echo '4-of-5 unexpectedly passed with only 3 successes' >&2
  exit 23
fi
'@
    $h1Text = $h1Text.Replace('__CUSTOM__', $customCyg).Replace('__BLOCKCHECK__', $blockcheckCyg).Replace('__LIST__', $listCyg)
    [IO.File]::WriteAllText($h1Script, $h1Text.Replace("`r`n", "`n"), [Text.Encoding]::ASCII)
    $h1Out = Join-Path $temp 'h1.out.log'
    $h1Err = Join-Path $temp 'h1.err.log'
    $savedPath = $env:PATH
    try {
        $env:PATH = "$(Split-Path -Parent $bash);$env:PATH"
        $h1Process = Start-Process -FilePath $bash -ArgumentList @((& $cygpath -u -a $h1Script).Trim()) `
            -WorkingDirectory $temp -PassThru -NoNewWindow -RedirectStandardOutput $h1Out -RedirectStandardError $h1Err
    }
    finally { $env:PATH = $savedPath }
    $null = $h1Process.Handle
    if (-not $h1Process.WaitForExit(15000)) {
        Stop-Z2OProcessTree -Process $h1Process
        throw 'Exact blockcheck H1 contract test timed out.'
    }
    Assert-True ($h1Process.ExitCode -eq 0) `
        ("exact blockcheck H1 contract failed: " + [string](Get-Content $h1Err -Raw))

    $attemptFile = Join-Path $temp 'retry-attempt.txt'
    $attemptCyg = (& $cygpath -u -a $attemptFile).Trim()
    $retryStub = Join-Path $temp 'retry-stub.sh'
    $retryStubText = @'
#!/bin/bash
attempt=0
[ ! -f "$Z2O_TEST_ATTEMPT_FILE" ] || attempt=$(cat "$Z2O_TEST_ATTEMPT_FILE")
attempt=$((attempt+1))
printf '%s' "$attempt" >"$Z2O_TEST_ATTEMPT_FILE"
if [ "$attempt" = 1 ]; then
  i=0
  while [ "$i" -lt 12 ]; do
    echo "- curl_test_https_tls13 retry-progress-$i"
    sleep 0.25
    i=$((i+1))
  done
  echo '0 [main] bash 123 child_copy: cygheap read copy failed, Win32 error 299' >&2
  exit 42
fi
printf "1\tretry.test\tcurl_test_https_tls13\t4\tok\t'--strategy=retry-ok'\n" >"$MACHINE_REPORT"
echo '!!!!! AVAILABLE !!!!!'
exit 0
'@
    [IO.File]::WriteAllText($retryStub, $retryStubText.Replace("`r`n", "`n"), [Text.Encoding]::ASCII)
    $retryGroup = [pscustomobject]@{
        id = 'retry'; displayName = 'retry'; probeDomains = @('retry.test')
        protocols = @('https-tls13')
    }
    $retryRun = Invoke-Z2OBlockcheckRun -InstallRoot $root -Group $retryGroup -TestName custom `
        -ScanLevel quick -Repeats 1 -RunLabel retry-integration -MaxRunSeconds 2 -StallSeconds 2 `
        -AttemptWallSeconds 6 -OverallWallSeconds 15 -CygwinRetries 1 -BashPath $bash `
        -BlockcheckScriptPath $retryStub -RunRoot (Join-Path $temp 'retry-runs') `
        -EnvironmentOverrides @{ Z2O_TEST_ATTEMPT_FILE = $attemptCyg }
    Assert-True ($retryRun.Attempts -eq 2) 'retry must execute attempt 2 after a renewed attempt 1 lease (B3/H4)'
    Assert-True ($retryRun.LeaseRenewals -ge 1) 'attempt 1 must prove the extended-lease branch executed'
    Assert-True ($retryRun.Records.Count -eq 1 -and $retryRun.Records[0].Strategy -match 'retry-ok') `
        'attempt 2 must return its complete machine result'

    # B2 salvage contract: a completed machine record is trustworthy even when
    # a Cygwin descendant later makes bash exit nonzero.
    $salvageStub = Join-Path $temp 'salvage-stub.sh'
    $salvageStubText = @'
#!/bin/bash
printf "1\tsalvage.test\tcurl_test_https_tls13\t4\tok\t'--strategy=salvaged'\n" >"$MACHINE_REPORT"
echo '0 [main] curl 456 child_copy: cygheap read copy failed, Win32 error 299' >&2
exit 42
'@
    [IO.File]::WriteAllText($salvageStub, $salvageStubText.Replace("`r`n", "`n"), [Text.Encoding]::ASCII)
    $salvageGroup = [pscustomobject]@{
        id = 'salvage'; displayName = 'salvage'; probeDomains = @('salvage.test')
        protocols = @('https-tls13')
    }
    $salvageRun = Invoke-Z2OBlockcheckRun -InstallRoot $root -Group $salvageGroup -TestName custom `
        -ScanLevel quick -Repeats 1 -RunLabel salvage-integration -MaxRunSeconds 5 -StallSeconds 2 `
        -CygwinRetries 1 -AllowPartialAtLimit -BashPath $bash -BlockcheckScriptPath $salvageStub `
        -RunRoot (Join-Path $temp 'salvage-runs')
    Assert-True ($salvageRun.Status -eq 'partial' -and $salvageRun.Attempts -eq 1) `
        'complete records must be salvaged without destructive retry after child stderr (B2)'
    Assert-True ($salvageRun.Records.Count -eq 1) 'salvaged machine record must survive'

    $stdout = Join-Path $temp 'progress.log'
    $stderr = Join-Path $temp 'progress.err.log'
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    $progressScript = Join-Path $temp 'progress.ps1'
    @"
for (`$i = 0; `$i -lt 12; `$i++) {
    Add-Content -LiteralPath '$stdout' -Value "- curl_test_https_tls12 test `$i"
    Start-Sleep -Milliseconds 250
}
"@ | Set-Content -LiteralPath $progressScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $progressScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-progress-renewal-test' -MaxRunSeconds 2 -StallSeconds 2 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'completed') 'recent semantic progress must renew the soft runtime lease'
        Assert-True ($outcome.LeaseRenewals -ge 1) 'a run that crosses its soft limit must record a lease renewal'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    Assert-True (Wait-ProcessGone -Id $process.Id) 'a progressing process must finish normally'

    $stdout = Join-Path $temp 'fresh-output.log'
    $stderr = Join-Path $temp 'fresh-output.err.log'
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    $freshOutputScript = Join-Path $temp 'fresh-output.ps1'
    @"
for (`$i = 0; `$i -lt 12; `$i++) {
    Add-Content -LiteralPath '$stdout' -Value "live blockcheck diagnostic `$i"
    Start-Sleep -Milliseconds 250
}
"@ | Set-Content -LiteralPath $freshOutputScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $freshOutputScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-fresh-output-renewal-test' -MaxRunSeconds 2 -StallSeconds 2 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'completed') 'fresh blockcheck output must renew the soft runtime lease'
        Assert-True ($outcome.LeaseRenewals -ge 1) 'fresh output past the soft limit must record a lease renewal'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    Assert-True (Wait-ProcessGone -Id $process.Id) 'a live output-producing process must finish normally'

    $stdout = Join-Path $temp 'limit.log'
    $stderr = Join-Path $temp 'limit.err.log'
    $childPidPath = Join-Path $temp 'limit-child.pid'
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    $limitScript = Join-Path $temp 'limit.ps1'
    @"
`$child = Start-Process -FilePath ping.exe -ArgumentList @('-t', '127.0.0.1') -PassThru
Set-Content -LiteralPath '$childPidPath' -Value `$child.Id -Encoding ASCII
Start-Sleep -Seconds 30
"@ | Set-Content -LiteralPath $limitScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $limitScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-no-output-limit-test' -MaxRunSeconds 2 -StallSeconds 8 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'limit') 'a run with no output must not renew the soft limit'
        Assert-True ($outcome.LeaseRenewals -eq 0) 'no-output run must not record a lease renewal'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    $childId = [int](Get-Content -LiteralPath $childPidPath -Raw)
    Assert-True (Wait-ProcessGone -Id $process.Id) 'soft-limit watchdog must stop the parent process'
    Assert-True (Wait-ProcessGone -Id $childId) 'soft-limit watchdog must stop the child process tree'

    $fakeRoot = Join-Path $temp 'private-root'
    $fakeBin = Join-Path $fakeRoot 'vendor\cygwin\bin'
    New-Item -ItemType Directory -Path $fakeBin -Force | Out-Null
    $fakeRunner = Join-Path $fakeBin 'orphan-runner.exe'
    Copy-Item -LiteralPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Destination $fakeRunner
    $orphanPidPath = Join-Path $temp 'orphan.pid'
    $orphanScript = Join-Path $temp 'orphan.ps1'
    @"
Set-Content -LiteralPath '$orphanPidPath' -Value `$PID -Encoding ASCII
Start-Sleep -Seconds 30
"@ | Set-Content -LiteralPath $orphanScript -Encoding ASCII
    $launcherScript = Join-Path $temp 'launch-orphan.ps1'
    @"
Start-Process -FilePath '$fakeRunner' -ArgumentList @('-NoLogo', '-NoProfile', '-File', '"$orphanScript"')
"@ | Set-Content -LiteralPath $launcherScript -Encoding ASCII
    $baseline = @(Get-Z2OInstallProcessIds -InstallRoot $fakeRoot)
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $launcherScript)) `
        -PassThru -NoNewWindow
    $process.WaitForExit()
    $deadline = (Get-Date).AddSeconds(5)
    while (-not (Test-Path -LiteralPath $orphanPidPath) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    Assert-True (Test-Path -LiteralPath $orphanPidPath) 'orphan test process must start from the private payload'
    $orphanId = [int](Get-Content -LiteralPath $orphanPidPath -Raw)
    Stop-Z2OBlockcheckProcessTree -Process $process -InstallRoot $fakeRoot -BaselineProcessIds $baseline
    Assert-True (Wait-ProcessGone -Id $orphanId) 'cleanup must stop an orphan after its bash-like parent already exited'

    Write-Host 'All watchdog behavior tests passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
