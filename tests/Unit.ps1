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
        probeDomains = @('alpha.test', 'beta.test')
        protocols = @('https-tls12', 'https-tls13')
    }
    $common = @(Get-Z2OCommonCandidates -Records $records -Group $group -Kind tls -IpVersion 4)
    Assert-True ($common.Count -eq 1) 'TLS intersection must contain one strategy'
    Assert-True ($common[0].Strategy -like "*--out-range=<s1*") 'strategy quoting must be preserved'

    $quoted = ConvertTo-Z2OWordexpToken -Value "a'b"
    Assert-True ($quoted -eq "'a'`"'`"'b'") 'single quote must be wordexp-safe'

    $install = Join-Path $temp 'install'
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

    Write-Host 'All unit tests passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
