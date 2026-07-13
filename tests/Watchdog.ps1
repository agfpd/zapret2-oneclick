$ErrorActionPreference = 'Stop'
$module = Join-Path (Split-Path -Parent $PSScriptRoot) 'launcher\Zapret2OneClick.psm1'
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
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    $cygwinScript = Join-Path $temp 'cygwin.ps1'
    @"
Set-Content -LiteralPath '$stderr' -Value '0 [main] curl 123 child_copy: cygheap read copy failed, Win32 error 299' -Encoding ASCII
Start-Sleep -Seconds 30
"@ | Set-Content -LiteralPath $cygwinScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $cygwinScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-cygwin-test' -MaxRunSeconds 10 -StallSeconds 8 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'cygwin') 'Cygwin error 299 must abort and invalidate the attempt'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    Assert-True (Wait-ProcessGone -Id $process.Id) 'Cygwin-failed attempt must be stopped'

    $stdout = Join-Path $temp 'limit.log'
    $stderr = Join-Path $temp 'limit.err.log'
    $childPidPath = Join-Path $temp 'limit-child.pid'
    New-Item -ItemType File -Path $stdout, $stderr -Force | Out-Null
    $limitScript = Join-Path $temp 'limit.ps1'
    @"
`$child = Start-Process -FilePath ping.exe -ArgumentList @('-t', '127.0.0.1') -PassThru
Set-Content -LiteralPath '$childPidPath' -Value `$child.Id -Encoding ASCII
for (`$i = 0; `$i -lt 100; `$i++) {
    Add-Content -LiteralPath '$stdout' -Value "- curl_test_https_tls12 test `$i"
    Start-Sleep -Milliseconds 200
}
"@ | Set-Content -LiteralPath $limitScript -Encoding ASCII
    $process = Start-Process -FilePath powershell.exe `
        -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $limitScript)) `
        -PassThru -NoNewWindow
    try {
        $outcome = Wait-Z2OBlockcheckProcess -Process $process -StdoutPath $stdout -StderrPath $stderr `
            -DisplayName 'watchdog-limit-test' -MaxRunSeconds 2 -StallSeconds 8 -HeartbeatSeconds 1
        Assert-True ($outcome.Status -eq 'limit') 'progress must not bypass the total wall-clock limit'
    }
    finally {
        Stop-Z2OProcessTree -Process $process
    }
    $childId = [int](Get-Content -LiteralPath $childPidPath -Raw)
    Assert-True (Wait-ProcessGone -Id $process.Id) 'wall-clock watchdog must stop the parent process'
    Assert-True (Wait-ProcessGone -Id $childId) 'wall-clock watchdog must stop the child process tree'

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
