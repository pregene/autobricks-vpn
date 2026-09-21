param(
    [string]$Config = 'config\client-b.ini',
    [string]$BinaryDirectory = 'bin\windows\debug',
    [string]$ServerVpnAddress = '10.9.1.1'
)

# Run in an elevated PowerShell. This bounded smoke test stops its own client.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$logDirectory = Join-Path $root ('testdata\windows-client-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$summary = Join-Path $logDirectory 'summary.txt'
function Record([string]$Message) { Add-Content -LiteralPath $summary -Value $Message -Encoding UTF8 }

$process = $null
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator PowerShell is required for Wintun.'
    }
    $configPath = (Resolve-Path -LiteralPath $Config).Path
    $directory = (Resolve-Path -LiteralPath $BinaryDirectory).Path
    $env:WINTUN_DLL = Join-Path $directory 'wintun.dll'
    $env:AUTOBRICKS_VPN_LIBRARY = Join-Path $directory 'autobricks_vpn.dll'
    $beforeRoutes = Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric
    $beforeRoutes | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $logDirectory 'routes-before.csv')
    Get-DnsClientNrptRule | Select-Object Name,Namespace,NameServers,Comment | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $logDirectory 'dns-before.csv')
    Record "Config: $configPath"
    Record "Started: $(Get-Date -Format o)"
    $process = Start-Process -FilePath (Join-Path $directory 'vpn-client.exe') `
        -ArgumentList @('--config', ('"' + $configPath + '"')) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logDirectory 'client.stdout.log') `
        -RedirectStandardError (Join-Path $logDirectory 'client.stderr.log')
    $null = $process.Handle
    $deadline = (Get-Date).AddSeconds(35)
    do {
        Start-Sleep -Milliseconds 500
        $process.Refresh()
        $connected = Select-String -LiteralPath (Join-Path $logDirectory 'client.stdout.log') -Pattern 'Rust VPN client connected' -Quiet
    } while (-not $process.HasExited -and -not $connected -and (Get-Date) -lt $deadline)
    if ($process.HasExited) {
        Record "Client exited before tunnel test: $($process.ExitCode)"
    } else {
        Start-Sleep -Seconds 5
        & ping.exe -n 8 -w 1500 $ServerVpnAddress | Out-File -Encoding UTF8 (Join-Path $logDirectory 'ping.txt')
        Record "Tunnel ping exit: $LASTEXITCODE"
        Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $logDirectory 'routes-connected.csv')
    }
} catch {
    Record "Error: $($_.Exception.Message)"
} finally {
    if ($process -and -not $process.HasExited) {
        $stopScript = Join-Path $PSScriptRoot 'stop-windows-client.ps1'
        $stopper = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $stopScript + '"'),
            '-ClientProcessId', $process.Id)
        $null = $stopper.Handle
        $stopper.WaitForExit()
        Record "Ctrl+C helper exit: $($stopper.ExitCode)"
        $process.WaitForExit(10000) | Out-Null
        if (-not $process.HasExited) {
            Record 'Graceful shutdown failed; terminating the test client.'
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit()
        }
    }
    if ($process) { Record "Final client exit: $($process.ExitCode)" }
    try {
        Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $logDirectory 'routes-after.csv')
        Get-DnsClientNrptRule -ErrorAction Stop | Select-Object Name,Namespace,NameServers,Comment | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $logDirectory 'dns-after.csv')
    } catch { Record "Cleanup inspection: $($_.Exception.Message)" }
    Record "Finished: $(Get-Date -Format o)"
}
