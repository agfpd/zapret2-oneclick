function ConvertTo-Z2OCygwinPath {
    param([Parameter(Mandatory)][string]$InstallRoot, [Parameter(Mandatory)][string]$Path)
    $cygpath = Join-Path $InstallRoot 'vendor\cygwin\bin\cygpath.exe'
    $value = & $cygpath -u -a $Path
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) {
        throw "cygpath failed for $Path"
    }
    return ([string]$value).Trim()
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
    $records = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        $parts = $line -split "`t", 5
        if ($parts.Count -ne 5) { throw "Malformed blockcheck machine report line: $line" }
        $records += [pscustomobject]@{
            Sequence = [int]$parts[0]
            Domain = $parts[1]
            Test = $parts[2]
            IpVersion = [int]$parts[3]
            Strategy = $parts[4].Trim()
        }
    }
    return $records
}

function Invoke-Z2OBlockcheckRun {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][string]$TestName,
        [Parameter(Mandatory)][ValidateSet('standard', 'force')][string]$ScanLevel,
        [Parameter(Mandatory)][int]$Repeats,
        [Parameter(Mandatory)][string]$RunLabel
    )

    $runDirectory = Join-Path $InstallRoot ('runtime\runs\{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $RunLabel)
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $machinePath = Join-Path $runDirectory 'machine.tsv'
    $stdoutPath = Join-Path $runDirectory 'blockcheck.log'
    $stderrPath = Join-Path $runDirectory 'blockcheck.err.log'

    $zapretRoot = Join-Path $InstallRoot 'vendor\zapret2'
    $bash = Join-Path $InstallRoot 'vendor\cygwin\bin\bash.exe'
    $cygBin = Join-Path $InstallRoot 'vendor\cygwin\bin'
    $cygLocalBin = Join-Path $InstallRoot 'vendor\cygwin\usr\local\bin'
    $scriptPath = ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path (Join-Path $zapretRoot 'blockcheck2.sh')
    $curlPath = ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path (Join-Path $cygLocalBin 'curl.exe')
    $machineCyg = ConvertTo-Z2OCygwinPath -InstallRoot $InstallRoot -Path $machinePath

    $protocols = @($Group.protocols)
    $variables = @{
        BATCH = '1'
        TEST = $TestName
        DOMAINS = (@($Group.probeDomains) -join ' ')
        IPVS = (Get-Z2OIpMode)
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
        CURL = $curlPath
        MACHINE_REPORT = $machineCyg
    }

    $saved = @{}
    try {
        foreach ($entry in $variables.GetEnumerator()) {
            $saved[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        }
        $saved['PATH'] = $env:PATH
        $env:PATH = "$cygBin;$cygLocalBin;$env:SystemRoot\System32;$env:SystemRoot"

        Write-Host "blockcheck2: $($Group.displayName), test=$TestName, scan=$ScanLevel, repeats=$Repeats" -ForegroundColor Cyan
        $process = Start-Process -FilePath $bash -ArgumentList @($scriptPath) -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -NoNewWindow
        if ($process.ExitCode -ne 0) {
            throw "blockcheck2 failed for $($Group.id), exit $($process.ExitCode). Logs: $stdoutPath, $stderrPath"
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
        [Parameter(Mandatory)][object[]]$Records,
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

    $eligible = @($Records | Where-Object { $_.IpVersion -eq $IpVersion -and $requiredTests -contains $_.Test })
    $result = @()
    foreach ($grouped in ($eligible | Group-Object Strategy)) {
        $keys = @($grouped.Group | ForEach-Object { "$($_.Domain)`t$($_.Test)" } | Sort-Object -Unique)
        $missing = @($requiredKeys | Where-Object { $keys -notcontains $_ })
        if ($missing.Count -eq 0) {
            $result += [pscustomobject]@{
                Kind = $Kind
                IpVersion = $IpVersion
                Strategy = $grouped.Name
                Order = ($grouped.Group | Measure-Object Sequence -Minimum).Minimum
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

function Get-Z2OProductionPenalty {
    param([Parameter(Mandatory)][string]$Strategy)
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
            }
            $all += $found
        }
    }
    return $all
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

    $tls = @($Candidates | Where-Object Kind -eq 'tls' | Sort-Object Order | Select-Object -ExpandProperty Strategy -Unique)
    $quic = @($Candidates | Where-Object Kind -eq 'quic' | Sort-Object Order | Select-Object -ExpandProperty Strategy -Unique)
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
        [Parameter(Mandatory)][object[]]$Candidates
    )
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
            -ScanLevel force -Repeats 5 -RunLabel "$($Group.id)-validation"
        $validated = @(Get-Z2OCandidatesFromRun -Run $run -Group $validationGroup)
        $selected = @()
        foreach ($version in @($Candidates | Select-Object -ExpandProperty IpVersion -Unique)) {
            foreach ($kind in @(Get-Z2OExpectedKinds -Group $Group)) {
                $order = @($Candidates | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind } |
                    Sort-Object @{ Expression = { Get-Z2OProductionPenalty -Strategy $_.Strategy } }, Order)
                $validStrategies = @($validated | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind } | Select-Object -ExpandProperty Strategy)
                $winner = $order | Where-Object { $validStrategies -contains $_.Strategy } | Select-Object -First 1
                if (-not $winner) { throw "No stable $kind strategy for $($Group.id), IPv$version." }
                $selected += $winner
            }
        }
        return $selected
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
        [Parameter(Mandatory)][object[]]$Selections
    )
    $runtime = Join-Path $InstallRoot 'runtime'
    New-Item -ItemType Directory -Path $runtime -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $runtime 'writable') -Force | Out-Null
    Backup-Z2OActiveConfig -InstallRoot $InstallRoot

    $lines = New-Object System.Collections.Generic.List[string]
    $zapret = Join-Path $InstallRoot 'vendor\zapret2'
    $luaLib = ConvertTo-Z2OConfigPath (Join-Path $zapret 'lua\zapret-lib.lua')
    $luaAntidpi = ConvertTo-Z2OConfigPath (Join-Path $zapret 'lua\zapret-antidpi.lua')
    $discordMedia = ConvertTo-Z2OConfigPath (Join-Path $zapret 'windivert.filter\windivert_part.discord_media.txt')
    $stun = ConvertTo-Z2OConfigPath (Join-Path $zapret 'windivert.filter\windivert_part.stun.txt')
    $writable = ConvertTo-Z2OConfigPath (Join-Path $runtime 'writable')

    $lines.Add((ConvertTo-Z2OWordexpToken "--writable=$writable"))
    $lines.Add((ConvertTo-Z2OWordexpToken "--lua-init=@$luaLib"))
    $lines.Add((ConvertTo-Z2OWordexpToken "--lua-init=@$luaAntidpi"))
    $lines.Add((ConvertTo-Z2OWordexpToken '--wf-tcp-out=443'))
    if (@($Selections | Where-Object Kind -eq 'quic').Count -gt 0) {
        $lines.Add((ConvertTo-Z2OWordexpToken '--wf-udp-out=443'))
    }
    $lines.Add((ConvertTo-Z2OWordexpToken "--wf-raw-part=@$discordMedia"))
    $lines.Add((ConvertTo-Z2OWordexpToken "--wf-raw-part=@$stun"))

    $profileIndex = 0
    foreach ($selection in ($Selections | Sort-Object GroupId, IpVersion, Kind)) {
        if ($profileIndex -gt 0) { $lines.Add((ConvertTo-Z2OWordexpToken '--new')) }
        $profileIndex++
        $group = @($Catalog.groups | Where-Object id -eq $selection.GroupId)[0]
        $hostlist = ConvertTo-Z2OConfigPath (Join-Path $InstallRoot ('config\' + $group.hostlist.Replace('/', '\')))
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

function Invoke-Z2OStrategySelectionCore {
    param([Parameter(Mandatory)][string]$InstallRoot, [Parameter(Mandatory)]$Catalog)
    $selections = @()
    foreach ($group in @($Catalog.groups)) {
        # Start with upstream's short custom list. It contains the current
        # high-value TLS/QUIC candidates and keeps first-run latency bounded.
        # Missing coverage escalates to the exhaustive standard suite below.
        $discoverySuite = if ($group.PSObject.Properties.Name -contains 'strategySuite') { [string]$group.strategySuite } else { 'custom' }
        $discovery = Invoke-Z2OBlockcheckRun -InstallRoot $InstallRoot -Group $group -TestName $discoverySuite `
            -ScanLevel standard -Repeats 1 -RunLabel "$($group.id)-discovery"
        $candidates = @(Get-Z2OCandidatesFromRun -Run $discovery -Group $group)

        $expected = @(Get-Z2OExpectedKinds -Group $group)
        $versions = if ((Get-Z2OIpMode) -eq '46') { @(4, 6) } else { @(4) }
        $incomplete = $false
        foreach ($version in $versions) {
            foreach ($kind in $expected) {
                if (@($candidates | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind }).Count -eq 0) {
                    $incomplete = $true
                }
            }
        }

        if ($incomplete) {
            Write-Warning "No common discovery candidate for $($group.id); running selective force scan."
            $forced = Invoke-Z2OBlockcheckRun -InstallRoot $InstallRoot -Group $group -TestName 'standard' `
                -ScanLevel force -Repeats 1 -RunLabel "$($group.id)-force"
            $candidates = @(Get-Z2OCandidatesFromRun -Run $forced -Group $group)
        }
        foreach ($version in $versions) {
            foreach ($kind in $expected) {
                if (@($candidates | Where-Object { $_.IpVersion -eq $version -and $_.Kind -eq $kind }).Count -eq 0) {
                    throw "No $kind strategy found for $($group.id), IPv$version after force scan."
                }
            }
        }

        $stable = @(Select-Z2OStableStrategies -InstallRoot $InstallRoot -Group $group -Candidates $candidates)
        foreach ($item in $stable) {
            $selections += [pscustomobject]@{
                GroupId = $group.id
                Kind = $item.Kind
                IpVersion = $item.IpVersion
                Strategy = $item.Strategy
                DiscoveryOrder = $item.Order
                Degraded = [bool]$item.Degraded
                ValidatedProtocols = @($item.ValidatedProtocols)
            }
        }
    }
    return $selections
}
