param([Parameter(Mandatory=$true)][int]$ClientProcessId)
# Console attachment is isolated from the test host, which must retain its own
# console for PowerShell's network inspection cmdlets after client shutdown.
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class VpnStopConsole {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint signal, uint group);
}
'@
[VpnStopConsole]::FreeConsole() | Out-Null
if (-not [VpnStopConsole]::AttachConsole([uint32]$ClientProcessId)) { exit 1 }
[VpnStopConsole]::SetConsoleCtrlHandler([IntPtr]::Zero, $true) | Out-Null
$sent = [VpnStopConsole]::GenerateConsoleCtrlEvent(0, 0)
Start-Sleep -Milliseconds 300
if ($sent) { exit 0 } else { exit 1 }
