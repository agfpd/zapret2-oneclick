[CmdletBinding()]
param(
    [ValidateSet('CompileOnly', 'SelfTest', 'TraceServiceOne', 'RunAB')][string]$Mode = 'TraceServiceOne',
    [ValidateRange(1, 5000)][int]$Iterations = 1000,
    [string]$EvidenceRoot,
    [string[]]$CaseFilter = @(),
    [ValidatePattern('^[a-zA-Z0-9._-]+$')][string]$EvidencePrefix = 'pe-flags-ab'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $env:TEMP ('z2o-pe-ab-evidence-' + [Guid]::NewGuid().ToString('N'))
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-DllCharacteristics {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    return [BitConverter]::ToUInt16($bytes, $pe + 24 + 70)
}

function ConvertTo-NonNullString {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [string]$Value
}

function Set-AslrBits {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][bool]$Enabled)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    $offset = $pe + 24 + 70
    $value = [BitConverter]::ToUInt16($bytes, $offset)
    if ($Enabled) { $value = $value -bor 0x60 } else { $value = $value -band 0xff9f }
    [Array]::Copy([BitConverter]::GetBytes([uint16]$value), 0, $bytes, $offset, 2)
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Get-ProductSnapshot {
    $service = Get-CimInstance Win32_Service -Filter "Name='zapret2-oneclick'" -ErrorAction SilentlyContinue
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='winws2.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        $process = Get-Process -Id ([int]$_.ProcessId) -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Id = [int]$_.ProcessId
            ExecutablePath = [string]$_.ExecutablePath
            StartTime = if ($process) { $process.StartTime.ToString('o') } else { $null }
        }
    })
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'" -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        ServiceState = if ($service) { [string]$service.State } else { $null }
        ServiceStartMode = if ($service) { [string]$service.StartMode } else { $null }
        WinDivertState = if ($driver) { [string]$driver.State } else { $null }
        Winws = $processes
    }
}

if (-not ('Z2OPeAB.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Z2OPeAB
{
    public sealed class TraceResult
    {
        public int ExitCode;
        public List<string> Images = new List<string>();
        public List<string> Events = new List<string>();
    }

    public static class Native
    {
        private const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        private const uint DBG_CONTINUE = 0x00010002;
        private const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        private const int EXCEPTION_DEBUG_EVENT = 1;
        private const int CREATE_PROCESS_DEBUG_EVENT = 3;
        private const int EXIT_PROCESS_DEBUG_EVENT = 5;
        private const int LOAD_DLL_DEBUG_EVENT = 6;
        private const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
        private const long HIGH_ENTROPY_ASLR_ALWAYS_OFF = 0x00000002L << 20;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint INFINITE = 0xffffffff;
        private const uint WAIT_TIMEOUT = 258;
        private const uint EXCEPTION_BREAKPOINT = 0x80000003;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
            public uint dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct CREATE_PROCESS_DEBUG_INFO
        {
            [FieldOffset(0)] public IntPtr hFile;
            [FieldOffset(8)] public IntPtr hProcess;
            [FieldOffset(16)] public IntPtr hThread;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct LOAD_DLL_DEBUG_INFO
        {
            [FieldOffset(0)] public IntPtr hFile;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct EXIT_PROCESS_DEBUG_INFO
        {
            [FieldOffset(0)] public uint dwExitCode;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct EXCEPTION_DEBUG_INFO
        {
            [FieldOffset(0)] public uint ExceptionCode;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct DEBUG_UNION
        {
            [FieldOffset(0)] public EXCEPTION_DEBUG_INFO Exception;
            [FieldOffset(0)] public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
            [FieldOffset(0)] public LOAD_DLL_DEBUG_INFO LoadDll;
            [FieldOffset(0)] public EXIT_PROCESS_DEBUG_INFO ExitProcess;
        }

        [StructLayout(LayoutKind.Explicit, Size = 176)]
        private struct DEBUG_EVENT
        {
            [FieldOffset(0)] public int dwDebugEventCode;
            [FieldOffset(4)] public uint dwProcessId;
            [FieldOffset(8)] public uint dwThreadId;
            [FieldOffset(16)] public DEBUG_UNION u;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size,
            IntPtr previous, IntPtr returnSize);
        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(
            string applicationName, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string currentDirectory, ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WaitForDebugEvent(out DEBUG_EVENT debugEvent, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ContinueDebugEvent(uint processId, uint threadId, uint status);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugSetProcessKillOnExit(bool killOnExit);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            IntPtr file, StringBuilder path, uint chars, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private static STARTUPINFOEX NewStartup()
        {
            STARTUPINFOEX value = new STARTUPINFOEX();
            value.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            return value;
        }

        private static string PathFromHandle(IntPtr file)
        {
            if (file == IntPtr.Zero || file == new IntPtr(-1)) return null;
            StringBuilder path = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(file, path, (uint)path.Capacity, 0);
            return length == 0 || length >= path.Capacity ? null : path.ToString();
        }

        public static TraceResult Trace(string file, string commandLine, string directory)
        {
            STARTUPINFOEX startup = NewStartup();
            PROCESS_INFORMATION pi;
            if (!CreateProcessW(file, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero,
                    false, DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, directory, ref startup, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW trace failed");
            DebugSetProcessKillOnExit(true);
            TraceResult result = new TraceResult();
            try
            {
                bool finished = false;
                bool initialBreakpointSeen = false;
                DateTime deadline = DateTime.UtcNow.AddSeconds(20);
                while (!finished)
                {
                    DEBUG_EVENT ev;
                    if (!WaitForDebugEvent(out ev, 1000))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != 121) throw new Win32Exception(error, "WaitForDebugEvent failed");
                        if (DateTime.UtcNow >= deadline)
                        {
                            TerminateProcess(pi.hProcess, 124);
                            throw new TimeoutException("Debug trace exceeded 20 seconds");
                        }
                        continue;
                    }
                    result.Events.Add(ev.dwDebugEventCode + ":" + ev.dwProcessId);
                    IntPtr imageHandle = IntPtr.Zero;
                    if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
                        imageHandle = ev.u.CreateProcessInfo.hFile;
                    else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
                        imageHandle = ev.u.LoadDll.hFile;
                    string image = PathFromHandle(imageHandle);
                    if (!String.IsNullOrEmpty(image)) result.Images.Add(image);
                    if (imageHandle != IntPtr.Zero && imageHandle != new IntPtr(-1)) CloseHandle(imageHandle);
                    if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
                    {
                        result.ExitCode = unchecked((int)ev.u.ExitProcess.dwExitCode);
                        finished = true;
                    }
                    uint continueStatus = DBG_CONTINUE;
                    if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                    {
                        uint code = ev.u.Exception.ExceptionCode;
                        result.Events.Add("exception:0x" + code.ToString("x8"));
                        if (code == EXCEPTION_BREAKPOINT && !initialBreakpointSeen)
                            initialBreakpointSeen = true;
                        else
                            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                    if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "ContinueDebugEvent failed");
                }
                return result;
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            }
        }

        public static int RunMitigated(string file, string commandLine, string directory)
        {
            IntPtr bytes = IntPtr.Zero, list = IntPtr.Zero, policy = IntPtr.Zero;
            bool initialized = false;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            try
            {
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
                if (bytes == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                list = Marshal.AllocHGlobal(bytes);
                if (!InitializeProcThreadAttributeList(list, 1, 0, ref bytes))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                initialized = true;
                policy = Marshal.AllocHGlobal(sizeof(long));
                Marshal.WriteInt64(policy, HIGH_ENTROPY_ASLR_ALWAYS_OFF);
                if (!UpdateProcThreadAttribute(list, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
                        policy, new IntPtr(sizeof(long)), IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                STARTUPINFOEX startup = NewStartup();
                startup.lpAttributeList = list;
                if (!CreateProcessW(file, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero,
                        false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, directory, ref startup, out pi))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW mitigated failed");
                uint wait = WaitForSingleObject(pi.hProcess, 20000);
                if (wait == WAIT_TIMEOUT)
                {
                    TerminateProcess(pi.hProcess, 124);
                    WaitForSingleObject(pi.hProcess, 5000);
                    return 124;
                }
                uint code;
                if (!GetExitCodeProcess(pi.hProcess, out code))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return unchecked((int)code);
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (initialized) DeleteProcThreadAttributeList(list);
                if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
                if (policy != IntPtr.Zero) Marshal.FreeHGlobal(policy);
            }
        }
    }
}
'@
}

if ($Mode -eq 'CompileOnly') {
    Write-Host 'PE A/B native harness compiled.'
    exit 0
}
if ($Mode -eq 'SelfTest') {
    $empty = ConvertTo-NonNullString -Value $null
    if ($empty -ne '') { throw 'Null normalization failed.' }
    if (@([regex]::Matches($empty, 'child_copy:.*failed')).Count -ne 0) {
        throw 'Empty stderr must contain no child failures.'
    }
    Write-Host 'PE A/B harness self-test passed.'
    exit 0
}

New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null

$expectedOfficial = '2bd9661d857794db6591510a92607da1d74e6da018887f19e832df68a9679275'
$expectedFixed = '40f1d2af4de4147cb6edecda97cd31e8c4d3d4cb2e087b66273adcb2b6d7fbb8'
$serviceSource = Join-Path $root 'vendor\zapret2\service'
$nfqSource = Join-Path $root 'vendor\zapret2\nfq2'
$cygBin = Join-Path $root 'vendor\cygwin\bin'
$work = Join-Path $env:TEMP ('z2o-pe-ab-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    $serviceFixed = Join-Path $work 'service-fixed'
    $serviceOfficial = Join-Path $work 'service-official'
    $blockFixed = Join-Path $work 'block-fixed'
    $blockOfficial = Join-Path $work 'block-official'
    foreach ($directory in @($serviceFixed, $serviceOfficial, $blockFixed, $blockOfficial)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $serviceSource 'WinDivert.dll') -Destination $directory
    }
    Copy-Item -LiteralPath (Join-Path $serviceSource 'cygwin1.dll') -Destination $serviceFixed
    Copy-Item -LiteralPath (Join-Path $serviceSource 'cygwin1.dll') -Destination $serviceOfficial
    Copy-Item -LiteralPath (Join-Path $serviceSource 'winws2.exe') -Destination $serviceFixed
    Copy-Item -LiteralPath (Join-Path $serviceSource 'winws2.exe') -Destination $serviceOfficial
    Copy-Item -LiteralPath (Join-Path $nfqSource 'winws2.exe') -Destination $blockFixed
    Copy-Item -LiteralPath (Join-Path $nfqSource 'winws2.exe') -Destination $blockOfficial
    Set-AslrBits -Path (Join-Path $serviceOfficial 'winws2.exe') -Enabled $true
    Set-AslrBits -Path (Join-Path $blockOfficial 'winws2.exe') -Enabled $true
    foreach ($path in @(
        (Join-Path $serviceFixed 'winws2.exe'), (Join-Path $blockFixed 'winws2.exe')
    )) {
        if ((Get-Sha256 $path) -ne $expectedFixed) { throw "Unexpected fixed hash: $path" }
    }
    foreach ($path in @(
        (Join-Path $serviceOfficial 'winws2.exe'), (Join-Path $blockOfficial 'winws2.exe')
    )) {
        if ((Get-Sha256 $path) -ne $expectedOfficial) { throw "Official reconstruction mismatch: $path" }
    }

    $before = Get-ProductSnapshot
    if ($Mode -eq 'TraceServiceOne') {
        $file = Join-Path $serviceFixed 'winws2.exe'
        $command = '"{0}" --dry-run --wf-l3=ipv4 --wf-tcp-out=65535' -f $file
        $trace = [Z2OPeAB.Native]::Trace($file, $command, $serviceFixed)
        $after = Get-ProductSnapshot
        $record = [pscustomobject]@{
            Mode = $Mode
            Timestamp = (Get-Date).ToString('o')
            Executable = $file
            ExecutableSha256 = Get-Sha256 $file
            DllCharacteristics = ('0x{0:x4}' -f (Get-DllCharacteristics $file))
            CygwinDllSha256 = Get-Sha256 (Join-Path $serviceFixed 'cygwin1.dll')
            ExitCode = $trace.ExitCode
            LoadedImages = @($trace.Images)
            DebugEvents = @($trace.Events)
            LoadedCygwin = @($trace.Images | Where-Object { $_ -match '(?i)\\cygwin1\.dll$' })
            LoadedWinDivert = @($trace.Images | Where-Object { $_ -match '(?i)\\WinDivert\.dll$' })
            WinDivertInitializedBanner = $false
            Before = $before
            After = $after
        }
        $path = Join-Path $EvidenceRoot 'trace-service-one.json'
        $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
        $record | ConvertTo-Json -Depth 8
        Write-Host "Evidence: $path"
        exit 0
    }

    function Invoke-Normal {
        param([string]$File, [string]$Directory)
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $File
        $start.Arguments = '--dry-run --wf-l3=ipv4 --wf-tcp-out=65535'
        $start.WorkingDirectory = $Directory
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        [void]$process.Start()
        $timedOut = -not $process.WaitForExit(20000)
        if ($timedOut) {
            try { $process.Kill() } catch { }
            $process.WaitForExit(5000) | Out-Null
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        return [pscustomobject]@{
            ExitCode = if ($timedOut) { 124 } else { $process.ExitCode }
            Stdout = $stdout
            Stderr = $stderr
            TimedOut = $timedOut
        }
    }

    function Stop-TestProcessTree {
        param([int]$ProcessId)
        $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
        $ids = New-Object Collections.Generic.List[int]
        $queue = New-Object Collections.Generic.Queue[int]
        $queue.Enqueue($ProcessId)
        while ($queue.Count -gt 0) {
            $id = $queue.Dequeue()
            foreach ($child in @($all | Where-Object { [int]$_.ParentProcessId -eq $id })) {
                $queue.Enqueue([int]$child.ProcessId)
            }
            $ids.Add($id)
        }
        [array]$ordered = $ids.ToArray()
        [array]::Reverse($ordered)
        foreach ($id in $ordered) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
    }

    function Invoke-BashChild {
        param([string]$File)
        $stdout = Join-Path $work ('stdout-' + [Guid]::NewGuid().ToString('N') + '.log')
        $stderr = Join-Path $work ('stderr-' + [Guid]::NewGuid().ToString('N') + '.log')
        $cygpath = Join-Path $cygBin 'cygpath.exe'
        $target = (& $cygpath -u -a $File).Trim()
        $oldTarget = $env:Z2O_PE_AB_TARGET
        $oldPath = $env:PATH
        try {
            $env:Z2O_PE_AB_TARGET = $target
            $env:PATH = "$cygBin;$env:PATH"
            $process = Start-Process -FilePath (Join-Path $cygBin 'bash.exe') `
                -ArgumentList @($bashWrapperCyg) `
                -WorkingDirectory (Split-Path -Parent $File) -PassThru -NoNewWindow `
                -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            $null = $process.Handle
            $timedOut = -not $process.WaitForExit(20000)
            if ($timedOut) {
                Stop-TestProcessTree -ProcessId $process.Id
                $process.WaitForExit(5000) | Out-Null
            }
            return [pscustomobject]@{
                ExitCode = if ($timedOut) { 124 } else { $process.ExitCode }
                Stdout = if (Test-Path $stdout) { Get-Content $stdout -Raw } else { '' }
                Stderr = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { '' }
                TimedOut = $timedOut
            }
        }
        finally {
            $env:Z2O_PE_AB_TARGET = $oldTarget
            $env:PATH = $oldPath
            Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
        }
    }

    $bashWrapper = Join-Path $work 'run-target.sh'
    $bashWrapperText = @'
#!/bin/bash
"$Z2O_PE_AB_TARGET" --dry-run --wf-l3=ipv4 --wf-tcp-out=65535
exit $?
'@
    [IO.File]::WriteAllText($bashWrapper, $bashWrapperText.Replace("`r`n", "`n"), [Text.Encoding]::ASCII)
    $bashWrapperCyg = (& (Join-Path $cygBin 'cygpath.exe') -u -a $bashWrapper).Trim()
    # Native-mitigation blockcheck cases inherit this process-local PATH, just
    # as the production helper inherits Invoke-Z2OBlockcheckRun's Cygwin PATH.
    $env:PATH = "$cygBin;$env:PATH"

    $cases = @(
        [pscustomobject]@{ Name='blockcheck-official-cygwin'; Type='bash'; File=(Join-Path $blockOfficial 'winws2.exe') },
        [pscustomobject]@{ Name='blockcheck-official-native-mitigation'; Type='mitigated'; File=(Join-Path $blockOfficial 'winws2.exe') },
        [pscustomobject]@{ Name='blockcheck-pefixed-cygwin'; Type='bash'; File=(Join-Path $blockFixed 'winws2.exe') },
        [pscustomobject]@{ Name='service-official-native'; Type='normal'; File=(Join-Path $serviceOfficial 'winws2.exe') },
        [pscustomobject]@{ Name='service-official-native-mitigation'; Type='mitigated'; File=(Join-Path $serviceOfficial 'winws2.exe') },
        [pscustomobject]@{ Name='service-pefixed-native'; Type='normal'; File=(Join-Path $serviceFixed 'winws2.exe') }
    )
    if ($CaseFilter.Count -gt 0) {
        $cases = @($cases | Where-Object { $name = $_.Name; @($CaseFilter | Where-Object { $name -like $_ }).Count -gt 0 })
        if ($cases.Count -eq 0) { throw 'CaseFilter selected no A/B cases.' }
    }
    $journalPath = Join-Path $EvidenceRoot ($EvidencePrefix + '-progress.ndjson')
    Remove-Item -LiteralPath $journalPath -Force -ErrorAction SilentlyContinue
    $results = @()
    foreach ($case in $cases) {
        $startupFailures = 0
        $childCopyFailures = 0
        $otherFailures = 0
        $timeouts = 0
        $firstFailure = $null
        for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
            [pscustomobject]@{
                Timestamp = (Get-Date).ToString('o')
                Case = $case.Name
                Iteration = $iteration
                State = 'starting-process'
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $journalPath -Encoding UTF8
            if ($case.Type -eq 'bash') {
                $run = Invoke-BashChild -File $case.File
            }
            elseif ($case.Type -eq 'mitigated') {
                $directory = Split-Path -Parent $case.File
                $command = '"{0}" --dry-run --wf-l3=ipv4 --wf-tcp-out=65535' -f $case.File
                $run = [pscustomobject]@{
                    ExitCode = [Z2OPeAB.Native]::RunMitigated($case.File, $command, $directory)
                    Stdout = ''
                    Stderr = ''
                    TimedOut = $false
                }
                if ($run.ExitCode -eq 124) { $run.TimedOut = $true }
            }
            else { $run = Invoke-Normal -File $case.File -Directory (Split-Path -Parent $case.File) }
            [pscustomobject]@{
                Timestamp = (Get-Date).ToString('o')
                Case = $case.Name
                Iteration = $iteration
                State = 'process-complete'
                ExitCode = [int]$run.ExitCode
                TimedOut = [bool]$run.TimedOut
                StderrBytes = [Text.Encoding]::UTF8.GetByteCount((ConvertTo-NonNullString -Value $run.Stderr))
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $journalPath -Encoding UTF8
            if ($run.TimedOut) { $timeouts++ }
            $stderrText = ConvertTo-NonNullString -Value $run.Stderr
            $stdoutText = ConvertTo-NonNullString -Value $run.Stdout
            $childCopyFailures += @([regex]::Matches($stderrText, 'child_copy:.*failed')).Count
            if ([int]$run.ExitCode -eq -1073741502) { $startupFailures++ }
            elseif ([int]$run.ExitCode -ne 0) { $otherFailures++ }
            if ([int]$run.ExitCode -ne 0 -and -not $firstFailure) {
                $firstFailure = [pscustomobject]@{
                    Iteration = $iteration
                    ExitCode = [int]$run.ExitCode
                    Stdout = $stdoutText.Substring(0, [Math]::Min(1000, $stdoutText.Length))
                    Stderr = $stderrText.Substring(0, [Math]::Min(1000, $stderrText.Length))
                }
            }
        }
        $results += [pscustomobject]@{
            Name = $case.Name
            Iterations = $Iterations
            ExecutableSha256 = Get-Sha256 $case.File
            DllCharacteristics = ('0x{0:x4}' -f (Get-DllCharacteristics $case.File))
            ChildCopyFailures = $childCopyFailures
            DllInitFailures = $startupFailures
            OtherFailures = $otherFailures
            Timeouts = $timeouts
            FirstFailure = $firstFailure
        }
    }
    $after = Get-ProductSnapshot
    $evidence = [pscustomobject]@{
        Mode = $Mode
        Timestamp = (Get-Date).ToString('o')
        IterationsPerCase = $Iterations
        ProgressJournal = $journalPath
        Before = $before
        Results = $results
        After = $after
    }
    $path = Join-Path $EvidenceRoot ($EvidencePrefix + '.json')
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    $evidence | ConvertTo-Json -Depth 8
    Write-Host "Evidence: $path"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
