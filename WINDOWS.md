# Windows 클라이언트 빌드와 테스트

Windows는 **클라이언트만 개발·지원**한다. x64/MSVC에서 `vpn-client.exe`와 `autobricks_vpn.dll`을 빌드하며, 서버는 Linux 또는 macOS에서 실행한다. Windows 서버 이식과 빌드는 개발 범위에서 제외한다.

## 준비

- Rust stable `x86_64-pc-windows-msvc`와 Cargo
- Visual Studio Build Tools 2022: MSVC C++ 도구와 Windows SDK
- CMake, Git, `curl.exe`, PowerShell
- 실제 VPN 실행에는 관리자 권한과 같은 아키텍처의 Wintun DLL

빌드 스크립트는 기존 Unix 빌드와 같은 wolfSSL `v5.8.2-stable`을 `dependens/`에서 빌드한다. DTLS 1.3, DTLS MTU, CRL, OCSP, OpenSSL 호환 API, IP SAN 옵션을 포함한다. Wintun 0.14.1 공식 ZIP을 다운로드하고 공식 SHA-256을 검증한다. 이미 준비된 wolfSSL과 Wintun 경로를 지정하면 다운로드 없이 재사용할 수 있다.

이 작업 폴더에 설치한 Rust는 `dependens/cargo`, `dependens/rustup`에 있다. `build.ps1`이 이 경로를 자동으로 사용하며 시스템 PATH는 변경하지 않는다. 새 체크아웃에서는 Rust를 먼저 설치해야 한다.

## 빌드

저장소 최상위에서 실행한다. 빌드 자체에는 관리자 권한이 필요하지 않으며 VPN 어댑터나 네트워크 설정을 변경하지 않는다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Test
# 최적화 빌드
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Release -Test
```

`-ExecutionPolicy Bypass`는 해당 PowerShell 프로세스에만 적용한다. 결과는 각각 `bin/windows/debug/`, `bin/windows/release/`에 배치한다.

```text
vpn-client.exe
autobricks_vpn.dll
wolfssl.dll
wintun.dll
```

EXE는 DLL을 불러오는 런처다. EXE의 `--help` 성공만으로 VPN 라이브러리 로딩이나 접속 성공을 판단하지 않는다. `-Test`는 라이브러리·클라이언트 런처 단위 테스트와 도움말 실행을 수행한다. 관리자 권한 VPN 접속 시험은 별도다.

기존 의존성을 재사용하는 예:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Test `
  -WolfSslPrefix .\dependens\wolfssl-install-windows `
  -WintunDll .\dependens\wintun-0.14.1\wintun\bin\amd64\wintun.dll
```

Cargo를 직접 실행할 때는 VPN DLL도 빌드한다. `WOLFSSL_PREFIX`에는 `lib/wolfssl.lib`, `bin/wolfssl.dll`이 필요하다.

```powershell
$env:WOLFSSL_PREFIX = "$PWD\dependens\wolfssl-install-windows"
cargo build --locked --target x86_64-pc-windows-msvc --features dtls13 --lib --bin vpn-client
```

## macOS/Linux 서버에 Windows 클라이언트 연결

관리자 PowerShell에서 저장소 최상위를 작업 디렉터리로 사용한다. INI의 상대 인증서 경로는 현재 작업 디렉터리를 기준으로 해석한다. `[certificate]`, `[key]`, `[ca]`가 내장된 INI는 내장 PEM이 우선한다.

```powershell
$env:WINTUN_DLL = "$PWD\bin\windows\debug\wintun.dll"
.\bin\windows\debug\vpn-client.exe --config .\config\client-b.ini
```

시험 대상은 사용자가 준비한 macOS 서버 `10.10.254.202:4433/UDP`, 서버 VPN 주소 `10.9.1.1`, 클라이언트 B 주소 `10.9.1.3`이다. 서버 인증서의 SAN IP도 `10.10.254.202`다. `verify_server_san_ip = true`를 권장한다. `false`이면 CA 인증서 체인 검증과 별개로 접속 주소의 SAN 일치 검사를 생략한다. 시험 초기에는 기존 설정의 `force_dns = false`를 유지한다.

로그에서 `DTLS handshake complete`와 `Rust VPN client connected`를 확인한 뒤 다른 터미널에서 실행한다.

```powershell
ping.exe -n 4 10.9.1.1
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 10.9.1.0/24
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0
```

외부 서버 주소에 대한 ping은 터널 통신 시험이 아니다. TCP 시험은 서버 VPN 주소에서 실제로 수신 중인 서비스의 포트로 수행한다. `Test-NetConnection -Port 4433`은 TCP 검사이므로 DTLS UDP 포트의 개방 여부를 증명하지 않는다.

종료는 Ctrl+C로 한다. 종료 후 VPN 어댑터·경로와 기존 기본 경로를 비교한다. DNS 강제 설정은 VPN DNS 서버 준비 후 별도로 시험하고, `Get-DnsClientNrptRule`의 VPN 규칙이 정상 종료 후 제거되는지 확인한다.

자동 접속·ping·종료 시험은 다음과 같다. 이 스크립트는 지정한 클라이언트만 시작하고 종료하며 기록은 `testdata/windows-client-날짜시각/`에 저장한다. 정상 종료에 실패해 강제 종료한 경우는 복구 검증 성공으로 처리하지 않는다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-windows-client.ps1 `
  -Config .\config\client-b.ini
```

## 오류와 검증 범위

- `Failed to create adapter`: 우선 관리자 권한, Wintun DLL 아키텍처 및 다른 프로세스의 어댑터 사용 여부를 확인한다.
- 소켓 오류 `10040`: Windows의 UDP `peek` 버퍼가 패킷보다 작을 때 발생할 수 있다. 현재 클라이언트는 `WSAPoll`로 수신 준비를 확인하며 1바이트 `peek`를 사용하지 않는다.
- DLL 로딩 실패: EXE, VPN DLL, wolfSSL DLL의 x64 아키텍처와 파일 배치를 확인한다.
- DTLS 시간 초과: UDP 경로·서버 로그·인증서·서버의 일시적 handshake ban을 구분해서 확인한다. 방화벽 전체를 끄는 것으로 대체하지 않는다.

2026-09-21 Windows x64/MSVC에서 클라이언트·VPN DLL debug/release 빌드, 단위 테스트, 실제 복사된 내장 인증서를 이용한 클라이언트 wolfSSL 초기화를 확인했다. Linux x86_64/macOS ARM64 대상 `cargo check --all-targets --all-features`도 확인했다. 이는 해당 OS의 실제 재실행 시험을 대신하지 않는다. Windows 클라이언트 → macOS 서버 DTLS 연결과 ICMP 8/8 응답, 정상 종료 및 경로 복구도 확인했다. 실제 시험 설정은 `verify_server_san_ip = false`, `force_dns = false`였으므로 SAN 검증·강제 DNS의 실제 접속/복구 성공을 의미하지 않는다. Windows 서버는 지원 대상이 아니다. 강제 DNS와 강제 종료 후 복구는 미검증이다. 자세한 결과는 [RESULT.md](RESULT.md)에 기록한다.

이후 사용자가 Windows 클라이언트 실행과 SSH 연결 성공을 확인했다. SSH 대상 주소·포트 및 세션 로그는 별도로 수집하지 않았고, TCP 처리량은 측정하지 않았다.

참고: [Cargo 빌드 대상](https://doc.rust-lang.org/cargo/commands/cargo-build.html), [wolfSSL 빌드](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html), [Wintun 공식 배포와 SHA-256](https://www.wintun.net/), [Windows netsh IPv4 설정](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface).
