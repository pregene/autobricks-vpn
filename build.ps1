param(
    [switch]$Release,
    [switch]$Test,
    [string]$WolfSslPrefix,
    [string]$WintunDll
)

# Windows x64 client build. Does not create adapters or change routes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$deps = Join-Path $root 'dependens'
$profile = if ($Release) { 'release' } else { 'debug' }
$target = 'x86_64-pc-windows-msvc'
$output = Join-Path $root "bin\windows\$profile"

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

Push-Location $root
try {
    New-Item -ItemType Directory -Force $deps | Out-Null
    # Reuse an isolated toolchain when one was installed in this checkout.
    $localCargo = Join-Path $deps 'cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $localCargo) {
        $env:CARGO_HOME = Join-Path $deps 'cargo'
        $env:RUSTUP_HOME = Join-Path $deps 'rustup'
        $env:PATH = "$(Join-Path $deps 'cargo\bin');$env:PATH"
    }
    if (-not (Get-Command cargo.exe -ErrorAction SilentlyContinue)) {
        throw 'Install Rust stable x86_64-pc-windows-msvc first; see WINDOWS.md.'
    }

    if (-not $WolfSslPrefix) {
        $WolfSslPrefix = Join-Path $deps 'wolfssl-install-windows'
        $source = Join-Path $deps 'wolfssl'
        $build = Join-Path $deps 'wolfssl-build-windows'
        if (-not (Test-Path -LiteralPath (Join-Path $source 'CMakeLists.txt'))) {
            Invoke-Checked git @('clone', '--depth', '1', '--branch', 'v5.8.2-stable',
                'https://github.com/wolfSSL/wolfssl.git', $source)
        }
        Invoke-Checked cmake @('-S', $source, '-B', $build, '-G', 'Visual Studio 17 2022', '-A', 'x64',
            "-DCMAKE_INSTALL_PREFIX=$WolfSslPrefix", '-DBUILD_SHARED_LIBS=ON',
            '-DWOLFSSL_DTLS=yes', '-DWOLFSSL_DTLS13=yes', '-DWOLFSSL_CRL=yes',
            '-DWOLFSSL_OCSP=yes', '-DWOLFSSL_OPENSSLEXTRA=yes', '-DWOLFSSL_IP_ALT_NAME=yes',
            '-DWOLFSSL_EXAMPLES=no', '-DWOLFSSL_CRYPT_TESTS=no',
            '-DWARNING_C_FLAGS=/W3', '-DCMAKE_C_FLAGS=/DWOLFSSL_DTLS_MTU')
        Invoke-Checked cmake @('--build', $build, '--config', 'Release', '--parallel', '4')
        Invoke-Checked cmake @('--install', $build, '--config', 'Release')
    }
    $WolfSslPrefix = (Resolve-Path -LiteralPath $WolfSslPrefix).Path
    foreach ($file in @('lib\wolfssl.lib', 'bin\wolfssl.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $WolfSslPrefix $file))) {
            throw "Missing wolfSSL artifact: $file under $WolfSslPrefix"
        }
    }

    if (-not $WintunDll) {
        $archive = Join-Path $deps 'wintun-0.14.1.zip'
        $unpacked = Join-Path $deps 'wintun-0.14.1'
        if (-not (Test-Path -LiteralPath $archive)) {
            Invoke-Checked curl.exe @('--fail', '--location', '--output', $archive,
                'https://www.wintun.net/builds/wintun-0.14.1.zip')
        }
        $expected = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
            throw 'Wintun archive SHA256 does not match the official release.'
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $unpacked -Force
        $WintunDll = Join-Path $unpacked 'wintun\bin\amd64\wintun.dll'
    }
    $WintunDll = (Resolve-Path -LiteralPath $WintunDll).Path
    $env:WOLFSSL_PREFIX = $WolfSslPrefix
    $env:PATH = "$(Join-Path $WolfSslPrefix 'bin');$env:PATH"
    $cargoArgs = @('build', '--locked', '--target', $target, '--features', 'dtls13', '--lib', '--bin', 'vpn-client')
    if ($Release) { $cargoArgs += '--release' }
    Invoke-Checked cargo.exe $cargoArgs

    New-Item -ItemType Directory -Force $output | Out-Null
    $artifacts = Join-Path $root "target\$target\$profile"
    foreach ($file in @('vpn-client.exe', 'autobricks_vpn.dll')) {
        Copy-Item -LiteralPath (Join-Path $artifacts $file) -Destination $output -Force
    }
    Copy-Item -LiteralPath (Join-Path $WolfSslPrefix 'bin\wolfssl.dll') -Destination $output -Force
    Copy-Item -LiteralPath $WintunDll -Destination (Join-Path $output 'wintun.dll') -Force
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $output -Force
    $wintunLicense = Join-Path $deps 'wintun-0.14.1\wintun\LICENSE.txt'
    if (Test-Path -LiteralPath $wintunLicense) {
        Copy-Item -LiteralPath $wintunLicense -Destination (Join-Path $output 'WINTUN-LICENSE.txt') -Force
    }
    $wolfLicense = Join-Path $deps 'wolfssl\COPYING'
    if (Test-Path -LiteralPath $wolfLicense) {
        Copy-Item -LiteralPath $wolfLicense -Destination (Join-Path $output 'WOLFSSL-COPYING') -Force
    }
    if ($Test) {
        $testArgs = @('test', '--locked', '--target', $target, '--features', 'dtls13', '--lib', '--bin', 'vpn-client')
        if ($Release) { $testArgs += '--release' }
        Invoke-Checked cargo.exe $testArgs
        Invoke-Checked (Join-Path $output 'vpn-client.exe') @('--help')
    }
    Write-Host "Build complete: $output"
    Write-Host 'VPN connection, adapter setup and DNS restoration require separate administrator runtime tests (WINDOWS.md).'
} finally {
    Pop-Location
}
