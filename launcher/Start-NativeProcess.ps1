[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PidFile,
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter(Mandatory)][string]$ArgumentFile
)

$ErrorActionPreference = 'Stop'

function ConvertTo-WindowsCommandLineArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $quoted = New-Object Text.StringBuilder
    [void]$quoted.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$quoted.Append(('\' * (($backslashes * 2) + 1)))
            [void]$quoted.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$quoted.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$quoted.Append($character)
    }
    if ($backslashes -gt 0) { [void]$quoted.Append(('\' * ($backslashes * 2))) }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Read-NulTerminatedUtf8Arguments {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $arguments = New-Object Collections.Generic.List[string]
    $start = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -ne 0) { continue }
        $arguments.Add([Text.Encoding]::UTF8.GetString($bytes, $start, $i - $start))
        $start = $i + 1
    }
    if ($start -ne $bytes.Length) {
        throw "Native child argument file is not NUL-terminated: $Path"
    }
    return $arguments.ToArray()
}

if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
    throw "Native child executable not found: $FilePath"
}
if (-not (Test-Path -LiteralPath $ArgumentFile -PathType Leaf)) {
    throw "Native child argument file not found: $ArgumentFile"
}

# Cygwin 3.6 keeps cygheap at a fixed 0x800000000..0xa00000000 range.
# The official winws2 image opts into high-entropy VA, so a Cygwin exec can
# occasionally map the image into that range and then fail child_copy with
# Win32 error 299. Create the exact official image from a native parent and
# turn off only high-entropy ASLR for this short-lived blockcheck child.
# Standard ASLR (DYNAMIC_BASE) remains enabled, and the service executable is
# never launched through this diagnostic-only helper.
if (-not ('Z2ONativeProcess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class Z2ONativeProcess
{
    private const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
    private const long HIGH_ENTROPY_ASLR_ALWAYS_OFF = 0x00000002L << 20;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
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
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    public static uint Start(string filePath, string commandLine, string workingDirectory)
    {
        IntPtr attributeBytes = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr mitigation = IntPtr.Zero;
        PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
        bool attributesInitialized = false;
        try
        {
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeBytes);
            if (attributeBytes == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to size process attribute list");

            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to initialize process attribute list");
            attributesInitialized = true;

            mitigation = Marshal.AllocHGlobal(sizeof(long));
            Marshal.WriteInt64(mitigation, HIGH_ENTROPY_ASLR_ALWAYS_OFF);
            if (!UpdateProcThreadAttribute(attributeList, 0,
                    new IntPtr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY), mitigation,
                    new IntPtr(sizeof(long)), IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to set child ASLR policy");

            STARTUPINFOEX startupInfo = new STARTUPINFOEX();
            startupInfo.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startupInfo.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startupInfo.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            startupInfo.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
            startupInfo.lpAttributeList = attributeList;

            StringBuilder mutableCommandLine = new StringBuilder(commandLine);
            if (!CreateProcessW(filePath, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, true,
                    EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, workingDirectory,
                    ref startupInfo, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create native child");

            uint wait = WaitForSingleObject(processInfo.hProcess, 200);
            if (wait != WAIT_TIMEOUT)
            {
                uint exitCode;
                if (!GetExitCodeProcess(processInfo.hProcess, out exitCode))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read native child exit code");
                throw new InvalidOperationException("Native child exited during startup with code " + exitCode);
            }
            return processInfo.dwProcessId;
        }
        finally
        {
            if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
            if (attributesInitialized) DeleteProcThreadAttributeList(attributeList);
            if (attributeList != IntPtr.Zero) Marshal.FreeHGlobal(attributeList);
            if (mitigation != IntPtr.Zero) Marshal.FreeHGlobal(mitigation);
        }
    }
}
'@
}

$childArguments = @(Read-NulTerminatedUtf8Arguments -Path $ArgumentFile)
$commandLine = (@(ConvertTo-WindowsCommandLineArgument -Value $FilePath) + @(
    $childArguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Value $_ }
)) -join ' '
Write-Verbose "Native child command line: $commandLine"
$childId = [Z2ONativeProcess]::Start(
    $FilePath,
    $commandLine,
    (Split-Path -Parent $FilePath)
)
[IO.File]::WriteAllText($PidFile, ([string]$childId + "`n"), [Text.Encoding]::ASCII)
