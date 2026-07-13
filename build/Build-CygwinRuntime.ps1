[CmdletBinding()]
param(
    [string]$WorkRoot = (Join-Path $env:TEMP 'z2o-cygwin-build'),
    [string]$Mirror = 'https://mirrors.kernel.org/sourceware/cygwin/',
    [string]$SetupUrl = 'https://cygwin.com/setup-x86_64.exe',
    [string]$SetupSha256 = '2c9f2fb56e1fb687b5d9680afa8f8b06e6214f0e483096af0eae1946431226c5',
    [string]$SetupExe,
    [string]$ExistingRoot,
    [string]$ExistingCache,
    [string]$WinBundleRoot,
    [string]$OutputRuntimeZip,
    [string]$OutputLock,
    [switch]$KeepWork
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputRuntimeZip) { $OutputRuntimeZip = Join-Path $repo 'artifacts\cygwin-runtime.tar.gz' }
if (-not $OutputLock) { $OutputLock = Join-Path $repo 'compliance\cygwin-packages.lock.json' }

$packages = @('bash','curl','coreutils','grep','sed','gawk','findutils','util-linux','procps-ng')
$setup = Join-Path $WorkRoot 'setup-x86_64.exe'
$root = if ($ExistingRoot) { $ExistingRoot } else { Join-Path $WorkRoot 'root' }
$cache = if ($ExistingCache) { $ExistingCache } else { Join-Path $WorkRoot 'cache' }
$runtime = Join-Path $WorkRoot 'runtime'

function Get-RelativePath([string]$Base, [string]$Path) {
    $baseUri = [Uri]((Resolve-Path -LiteralPath $Base).Path.TrimEnd('\') + '\')
    $pathUri = [Uri](Resolve-Path -LiteralPath $Path).Path
    [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace('/', '\')
}

function Parse-SetupIni([string]$Path) {
    $result = @{}
    $current = $null
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^@\s+(.+)$') {
            $current = $Matches[1]
            if (-not $result.ContainsKey($current)) { $result[$current] = @() }
        } elseif ($current -and $line -match '^(version|install|source):\s+(.+)$') {
            $field = $Matches[1]
            $value = $Matches[2]
            if ($field -eq 'version') {
                $result[$current] += [ordered]@{ version = $value }
            } elseif ($result[$current].Count -gt 0) {
                $parts = $value -split '\s+'
                $result[$current][-1][$field] = [ordered]@{
                    path = $parts[0]
                    size = [long]$parts[1]
                    sha512 = $parts[2]
                }
            }
        }
    }
    $result
}

if (($ExistingRoot -and -not $ExistingCache) -or ($ExistingCache -and -not $ExistingRoot)) {
    throw 'ExistingRoot and ExistingCache must be supplied together.'
}
if (Test-Path -LiteralPath $WorkRoot) {
    & cmd.exe /d /c "rmdir /s /q `"$WorkRoot`""
    if (Test-Path -LiteralPath $WorkRoot) { throw "Could not clean work root: $WorkRoot" }
}
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
if (-not $ExistingRoot) {
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    if ($SetupExe) {
        Copy-Item -LiteralPath $SetupExe -Destination $setup
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri $SetupUrl -OutFile $setup
    }
    $actualSetup = (Get-FileHash -Algorithm SHA256 -LiteralPath $setup).Hash.ToLowerInvariant()
    if ($actualSetup -ne $SetupSha256) { throw "Cygwin setup hash mismatch: $actualSetup" }

    $setupArgs = @(
        '--quiet-mode','--no-desktop','--no-startmenu','--no-admin','--no-write-registry',
        '--root', $root, '--local-package-dir', $cache, '--site', $Mirror,
        '--include-source','--packages', ($packages -join ',')
    )
    $setupProcess = Start-Process -FilePath $setup -ArgumentList $setupArgs -Wait -PassThru
    if ($setupProcess.ExitCode -ne 0) { throw "Cygwin setup failed with exit code $($setupProcess.ExitCode)" }
}

$installedDb = Join-Path $root 'etc\setup\installed.db'
$setupIni = Get-ChildItem -LiteralPath $cache -Recurse -Filter setup.ini | Select-Object -First 1
if (-not (Test-Path -LiteralPath $installedDb) -or -not $setupIni) { throw 'Cygwin package metadata is missing.' }
$index = Parse-SetupIni $setupIni.FullName
$mirrorCache = Split-Path -Parent (Split-Path -Parent $setupIni.FullName)
$locked = @()

foreach ($line in (Get-Content -LiteralPath $installedDb | Select-Object -Skip 1)) {
    if ($line -notmatch '^(\S+)\s+(\S+)\s+\d+$') { continue }
    $name = $Matches[1]
    $archiveName = $Matches[2]
    if (-not $index.ContainsKey($name)) { throw "Installed package '$name' is absent from setup.ini." }
    $record = $index[$name] | Where-Object {
        $_.install.path -and (
            ([IO.Path]::GetFileName($_.install.path) -eq $archiveName) -or
            ($archiveName -like "*-$($_.version).tar.*") -or
            ($archiveName -like "*-$($_.version)-*.tar.*")
        )
    } | Select-Object -First 1
    if (-not $record -or -not $record.source.path) { throw "No corresponding source metadata for $name/$archiveName." }
    $binaryFile = Join-Path $mirrorCache $record.install.path.Replace('/','\')
    $sourceFile = Join-Path $mirrorCache $record.source.path.Replace('/','\')
    foreach ($item in @(@($binaryFile,$record.install.sha512),@($sourceFile,$record.source.sha512))) {
        if (-not (Test-Path -LiteralPath $item[0])) { throw "Cached archive missing: $($item[0])" }
        $hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $item[0]).Hash.ToLowerInvariant()
        if ($hash -ne $item[1]) { throw "SHA-512 mismatch: $($item[0])" }
    }
    $locked += [ordered]@{
        name = $name
        version = $record.version
        binary = $record.install
        source = $record.source
    }
}

New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$excludeDirs = @((Join-Path $root 'usr\src'),(Join-Path $root 'usr\share\doc'),(Join-Path $root 'usr\share\info'),(Join-Path $root 'usr\share\man'),(Join-Path $root 'usr\share\locale'),(Join-Path $root 'home'),(Join-Path $root 'tmp'))
& robocopy $root $runtime /E /COPY:DAT /DCOPY:DAT /R:2 /W:1 /XD @excludeDirs | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }
New-Item -ItemType Directory -Force -Path (Join-Path $runtime 'tmp') | Out-Null

# Cygwin package archives contain magic-cookie symlinks. NTFS system attributes
# that make these links executable are not portable through Git/ZIP, so turn
# them into ordinary copies in the distributable runtime.
foreach ($file in Get-ChildItem -LiteralPath $runtime -Recurse -File | Where-Object { $_.Length -le 1024 }) {
    try { $bytes = [IO.File]::ReadAllBytes($file.FullName) }
    catch { continue }
    if ($bytes.Length -lt 11) { continue }
    $text = [Text.Encoding]::ASCII.GetString($bytes).TrimEnd([char]0)
    if (-not $text.StartsWith('!<symlink>')) { continue }
    $targetName = $text.Substring(10).Replace('/','\')
    if ($targetName.Contains([char]0)) {
        [IO.File]::SetAttributes($file.FullName, [IO.FileAttributes]::Normal)
        Remove-Item -LiteralPath $file.FullName -Force
        continue
    }
    $targetBase = if ($targetName.StartsWith('\')) { $runtime } else { $file.DirectoryName }
    $targetName = $targetName.TrimStart('\')
    try { $target = [IO.Path]::GetFullPath((Join-Path $targetBase $targetName)) }
    catch { throw "Invalid Cygwin link: $($file.FullName) -> $targetName" }
    [IO.File]::SetAttributes($file.FullName, [IO.FileAttributes]::Normal)
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        Copy-Item -LiteralPath $target -Destination $file.FullName -Force
    } elseif (Test-Path -LiteralPath $target -PathType Container) {
        Remove-Item -LiteralPath $file.FullName -Force
        New-Item -ItemType Directory -Force -Path $file.FullName | Out-Null
        Copy-Item -Path (Join-Path $target '*') -Destination $file.FullName -Recurse -Force
    } else {
        Write-Warning "Dropping unresolved optional Cygwin link: $($file.FullName) -> $targetName"
        Remove-Item -LiteralPath $file.FullName -Force
    }
}

if ($WinBundleRoot) {
    $custom = Join-Path $WinBundleRoot 'cygwin\usr\local'
    if (-not (Test-Path -LiteralPath (Join-Path $custom 'bin\curl.exe'))) { throw 'Pinned win-bundle HTTP/3 curl was not found.' }

    # The package solver installs a much wider base set than blockcheck2 needs.
    # Keep the proven portable-bundle inventory, replace matching files with the
    # current package versions above, and retain their current DLL dependencies.
    $templateRoot = Join-Path $WinBundleRoot 'cygwin'
    $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in Get-ChildItem -LiteralPath $templateRoot -Recurse -File) {
        $relative = Get-RelativePath -Base $templateRoot -Path $file.FullName
        if (-not $relative.StartsWith('usr\local\')) { [void]$allowed.Add($relative) }
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $runtime 'bin') -File -Filter '*.dll') {
        [void]$allowed.Add((Get-RelativePath -Base $runtime -Path $file.FullName))
    }
    [void]$allowed.Add('etc\setup\installed.db')
    foreach ($file in Get-ChildItem -LiteralPath $runtime -Recurse -File) {
        try { $relative = Get-RelativePath -Base $runtime -Path $file.FullName }
        catch { continue }
        if (-not $allowed.Contains($relative)) {
            try {
                [IO.File]::SetAttributes($file.FullName, [IO.FileAttributes]::Normal)
                Remove-Item -LiteralPath $file.FullName -Force
            } catch { }
        }
    }

    $customBin = Join-Path $runtime 'usr\local\bin'
    New-Item -ItemType Directory -Force -Path $customBin | Out-Null
    foreach ($name in @('curl.exe','cygcurl-4.dll','cygcrypto-3.dll','cygssl-3.dll','cygnghttp2-14.dll','cygnghttp3-9.dll','cygidn2-0.dll')) {
        $input = Join-Path $custom "bin\$name"
        if (-not (Test-Path -LiteralPath $input -PathType Leaf)) { throw "Pinned HTTP/3 curl dependency missing: $name" }
        Copy-Item -LiteralPath $input -Destination $customBin -Force
    }
}

$customSources = @(
    [ordered]@{ name='cygwin-service-runtime'; version='3.4.10-1'; url='https://ftp.cvut.cz/mirrors/cygwin.com/x86_64/release/cygwin/cygwin-3.4.10-1-src.tar.xz'; sha256='ac70af0d4e644732f74946f55f7bafe010bab9b9da39a9327c3f0367f1fa43a2' },
    [ordered]@{ name='curl-http3'; version='8.10.1'; url='https://curl.se/download/curl-8.10.1.tar.xz'; sha256='73a4b0e99596a09fa5924a4fb7e4b995a85fda0d18a2c02ab9cf134bebce04ee' },
    [ordered]@{ name='openssl'; version='3.4.0'; url='https://github.com/openssl/openssl/releases/download/openssl-3.4.0/openssl-3.4.0.tar.gz'; sha256='e15dda82fe2fe8139dc2ac21a36d4ca01d5313c75f99f46c4e8a27709b7294bf' },
    [ordered]@{ name='nghttp2'; version='1.61.0'; url='https://github.com/nghttp2/nghttp2/releases/download/v1.61.0/nghttp2-1.61.0.tar.xz'; sha256='c0e660175b9dc429f11d25b9507a834fb752eea9135ab420bb7cb7e9dbcc9654' },
    [ordered]@{ name='nghttp3'; version='1.6.0'; url='https://github.com/ngtcp2/nghttp3/releases/download/v1.6.0/nghttp3-1.6.0.tar.xz'; sha256='eaa901954bc494034d3738ef19130de69387d6a3da029044c60d9dae91792a8d' },
    [ordered]@{ name='libidn2'; version='2.3.8'; url='https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz'; sha256='f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a' }
)

$lock = [ordered]@{
    schemaVersion = 1
    status = 'complete'
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    setup = [ordered]@{ url=$SetupUrl; sha256=$SetupSha256; mirror=$Mirror }
    requestedPackages = $packages
    packages = $locked
    customSources = $customSources
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputLock) | Out-Null
$lock | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputLock -Encoding UTF8

if (Test-Path -LiteralPath $OutputRuntimeZip) { Remove-Item -LiteralPath $OutputRuntimeZip -Force }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputRuntimeZip) | Out-Null
$tar = Start-Process -FilePath 'tar.exe' -ArgumentList @('-czf',$OutputRuntimeZip,'--exclude=._*','-C',$runtime,'.') -Wait -PassThru
if ($tar.ExitCode -ne 0) { throw "tar.exe failed with exit code $($tar.ExitCode)" }
Write-Host "Runtime: $OutputRuntimeZip"
Write-Host "Lock:    $OutputLock"

if (-not $KeepWork -and (Test-Path -LiteralPath $WorkRoot)) {
    & cmd.exe /d /c "rmdir /s /q `"$WorkRoot`""
}
