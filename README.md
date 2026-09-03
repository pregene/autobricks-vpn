# autobricks-vpn

wolfSSL 기반 DTLS 1.3 VPN transport shared library와 서버/클라이언트 예제입니다.

```text
Autobricks VPN 1.0
Copyright © 2026 Autobricks.co.kr. All rights reserved.
```

## 지원 기능

| 구분 | 지원 내용 |
| --- | --- |
| 서버 운영체제 | Linux, macOS |
| 클라이언트 운영체제 | Linux, macOS, Windows (Wintun) |
| 전송 계층 | UDP 기반 wolfSSL DTLS 1.3, DTLS 재전송 및 DTLS 1.2 빌드 fallback |
| 터널 트래픽 | IPv4 unicast, TCP, UDP, ICMP |
| TUN 설정 | OS별 TUN 생성, IPv4 주소·MTU·VPN 대역 route 자동 설정 |
| 상호 인증 | CA 기반 서버/클라이언트 인증서 검증 |
| 클라이언트 할당 | 인증서 SHA-256 fingerprint별 고정 VPN IP |
| SAN 검증 | 서버 SAN IP 검증, 선택적인 클라이언트 SAN IP 검증 |
| 인증서 폐기 | CRL 및 OCSP(AIA URL 또는 override URL), 실패 시 연결 거부 |
| 세션 관리 | keepalive, idle timeout, 최대 세션 수명, 고정 3초 재연결, 재인증 |
| 설정 갱신 | 서버 인증서·키·CA와 client fingerprint binding 주기적 reload |
| 공격 방어 | stateless DTLS cookie, pending handshake 제한, 출발지 IP spoofing 방지, panic 격리 |
| 접속 제한 | 외부 IP별 1분 30회 handshake 시도 시 10분간 메모리 ban |
| 전달 정책 | 설정에 따른 IPv4 broadcast/multicast 허용 또는 폐기 |
| DNS | VPN DNS 강제 적용 및 정상 종료 시 복구 |
| 운영 로그 | 연결과 해지·세션 사용량을 syslog `local0.info`에 기록, rsyslog로 `/var/log/autobricks-vpn.log` 저장 가능 |
| Linux 전달 | 실행 파일이 IPv4 forwarding과 VPN client 간 iptables 규칙을 직접 관리 |

## 지원하지 않는 기능

- IPv6: 현재 제품 범위에 필요하지 않아 지원하지 않습니다.
- 외부 인터넷 또는 외부 LAN 접속: VPN 내부 통신 전용입니다.
- NAT/MASQUERADE 및 인터넷 default route 변경
- split DNS 또는 fallback DNS: `force_dns = true`이면 모든 DNS 질의가 지정한 VPN DNS를 사용합니다.
- Windows 서버
- 모바일 roaming 또는 연결 중 UDP endpoint의 NAT rebinding: 연결이 끊기면 새 DTLS 세션으로 재접속합니다.
- 무중단 기존 DTLS 세션의 인증서·키 교체: 최대 세션 수명 후 재접속하면서 새 인증 정보를 적용합니다.
- 자동 CRL 다운로드: `crl_file`로 지정한 로컬 CRL을 사용합니다.
- 영구 ban 저장: 접속 제한 정보는 프로세스 메모리에만 유지합니다.
- packet payload 로그 및 packet별 트래픽 로그
- Prometheus 같은 별도 metrics endpoint
- 경로 MTU 자동 탐색: 설정된 고정 TUN MTU를 사용합니다.

지원하지 않는 항목 중 IPv6, NAT 및 외부 인터넷 연결은 현재 설계 목적상 구현 대상이 아닙니다.

## 개발환경 구성

### 공통 요구사항

- Rust stable toolchain과 Cargo (Rust 2021 edition)
- C compiler와 linker
- wolfSSL header와 library
- 인증서 확인 및 테스트 인증서 생성을 위한 OpenSSL CLI
- 소스에서 wolfSSL을 빌드할 경우 Git, Autoconf, Automake, Libtool, Make, pkg-config

Rust는 rustup으로 설치하는 것을 권장합니다.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustc --version
cargo --version
```

전체 기능을 사용하는 개발용 wolfSSL은 DTLS 1.3, CRL 및 OCSP를 포함해 빌드합니다.
사용 가능한 옵션과 버전별 차이는 [wolfSSL 공식 빌드 문서](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html)를 기준으로 확인합니다.

```sh
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --prefix=/opt/wolfssl-autobricks \
  --enable-dtls --enable-dtls13 --enable-dtls-mtu \
  --enable-crl --enable-ocsp --enable-opensslextra \
  --enable-ip-alt-name
make -j4
sudo make install
```

프로젝트 빌드 시 설치 위치와 Rust의 DTLS 1.3 코드를 함께 지정합니다.

```sh
WOLFSSL_PREFIX=/opt/wolfssl-autobricks cargo build --features dtls13
```

`WOLFSSL_PREFIX` 아래에는 `include/wolfssl/`과 `lib/libwolfssl` shared/static library가 있어야 합니다. Rust의 `dtls13` feature만 켜거나 wolfSSL만 DTLS 1.3으로 빌드해서는 안 되며 두 설정이 일치해야 합니다. CRL/OCSP를 설정에서 활성화하려면 wolfSSL도 해당 기능을 포함해야 합니다. 인증서 fingerprint와 SAN 처리에 사용하는 X509 호환 API를 위해 `--enable-opensslextra`가 필요하고, IP Address SAN을 문자열로 열거하려면 `--enable-ip-alt-name`도 필요합니다. 서버 SAN IP는 DTLS 인증서 체인 검증이 완료된 뒤 인증서의 IP Address SAN을 직접 대조하므로 Homebrew wolfSSL에 없는 `wolfSSL_check_ip_address` 심볼에 의존하지 않습니다.

### Linux 개발환경

Ubuntu/Debian 기준 기본 도구는 다음과 같이 설치합니다.

```sh
sudo apt update
sudo apt install build-essential pkg-config git autoconf automake libtool openssl \
  iproute2 iptables systemd-resolved
```

배포판의 `libwolfssl-dev`도 사용할 수 있지만 DTLS 1.3, CRL 및 OCSP 포함 여부가 배포판마다 다릅니다. 위의 소스 빌드는 프로젝트의 전체 기능을 확인하기 위한 권장 구성입니다.

Linux 실행 환경에서는 `/dev/net/tun`과 `ip`, `iptables`, `sysctl`을 사용합니다. DNS 강제 적용을 테스트하려면 `resolvectl`을 제공하는 `systemd-resolved`가 실행 중이어야 합니다.

### macOS 개발환경

Xcode Command Line Tools와 Homebrew 개발 도구를 설치합니다.

```sh
xcode-select --install
brew install rust pkg-config autoconf automake libtool openssl@3
```

Homebrew의 wolfSSL 패키지로 기본 빌드를 시험할 수 있습니다.

```sh
brew install wolfssl
cargo build
```

DTLS 1.3과 CRL/OCSP를 모두 같은 설정으로 검증하려면 공통 절의 wolfSSL 소스 빌드를 사용하고 `WOLFSSL_PREFIX`를 지정합니다. macOS 실행 환경은 내장된 `ifconfig`, `route`, `networksetup`을 사용합니다.

### Windows 클라이언트 개발환경

Windows는 클라이언트만 빌드할 수 있습니다. 다음 항목이 필요합니다.

- Rust stable `x86_64-pc-windows-msvc` toolchain
- Visual Studio Build Tools의 Desktop development with C++ workload
- MSVC로 빌드한 wolfSSL (`include`와 `lib` 디렉터리)
- Wintun 배포 파일의 아키텍처에 맞는 `wintun.dll`

PowerShell에서 경로를 설정하고 빌드합니다.

```powershell
rustup default stable-x86_64-pc-windows-msvc
$env:WOLFSSL_PREFIX = "C:\wolfssl"
$env:WINTUN_DLL = "C:\path\to\wintun.dll"
cargo build --bin vpn-client --features dtls13
Copy-Item $env:WINTUN_DLL target\debug\wintun.dll
```

`C:\wolfssl` 아래에는 `include\wolfssl`과 링커가 찾을 수 있는 `lib\wolfssl.lib`가 있어야 합니다. wolfSSL과 Rust target은 같은 MSVC ABI와 CPU architecture로 빌드해야 합니다. 실행 시 Wintun adapter, IPv4 주소, route 및 NRPT DNS 규칙을 구성합니다.

### 개발 빌드 검증

```sh
cargo fmt --check
cargo check --all-targets --all-features
cargo test --lib
cargo clippy --all-targets --all-features
```

`cargo check`는 Rust 코드 검증만 수행할 수 있지만 실행 파일을 생성하는 `cargo build`와 실제 구동에는 wolfSSL library가 필요합니다. 테스트용 인증서 경로는 `certs/`이며 개인키는 Linux/macOS에서 소유자만 읽을 수 있도록 설정합니다.

```sh
chmod 600 certs/*-key.pem
```

### 클라이언트 실환경 검증 현황

| 클라이언트 환경 | 서버 환경 | 검증 항목 | 결과 |
| --- | --- | --- | --- |
| Ubuntu 22.04.5 LTS, x86_64, wolfSSL 5.9.1 | Ubuntu 22.04.4 LTS, x86_64 | DTLS 1.3 상호 인증, 인증서 fingerprint/SAN 기반 VPN IP 할당, TUN/MTU 1350, NAT·UDP 포트포워딩 경유 연결, ICMP, TCP/HTTP, VPN DNS, 클라이언트 간 통신 | 성공 |
| macOS 14.6.1, arm64, Rust 1.97.1, wolfSSL 5.9.1 | Ubuntu 22.04.4 LTS, x86_64 | DTLS 1.3 상호 인증, 인증서 fingerprint/SAN 기반 VPN IP 할당, utun/MTU 1350, NAT·UDP 포트포워딩 경유 연결, ICMP, TCP/HTTP, VPN DNS, Linux 클라이언트 접속 | 성공 |
| Windows | Ubuntu Linux | Wintun 생성, DTLS 연결, 인증서 검증, VPN route 및 실제 터널 통신 | 미검증 (테스트 예정) |

위 표의 성공은 빌드 또는 단위 테스트만의 결과가 아니라 실제 서버와 클라이언트를 실행해 터널 트래픽을 확인한 결과입니다. Windows 코드는 빌드 경로를 제공하지만 아직 실제 Windows 장비에서 검증하지 않았습니다.

## Build

VPN 구현이 들어 있는 동적 라이브러리와 이를 호출하는 `vpn-server`, `vpn-client` launcher를 Cargo로 빌드합니다.

```sh
brew install wolfssl
cargo build
```

wolfSSL이 `WOLFSSL_DTLS13`으로 빌드된 경우 DTLS 1.3 method를 사용합니다. 해당 옵션이 없는 배포 패키지에서는 빌드 검증을 위해 DTLS 1.2 method로 fallback하므로, production DTLS 1.3 배포에는 DTLS 1.3이 활성화된 wolfSSL을 직접 빌드해 링크해야 합니다.

CRL과 OCSP를 사용하려면 wolfSSL을 `--enable-crl --enable-ocsp` 옵션으로 빌드해야 합니다. 설정에서 해당 검증을 요청했는데 라이브러리가 지원하지 않으면 VPN은 폐기 검사를 생략하지 않고 시작을 중단합니다.

Linux에서는 wolfSSL 개발 패키지를 설치한 뒤 `WOLFSSL_PREFIX=/path/to/wolfssl cargo build`를 실행합니다. macOS에서는 `target/debug/libautobricks_vpn.dylib`, Linux에서는 `target/debug/libautobricks_vpn.so`가 생성됩니다.

빌드 결과는 다음 구조로 배치됩니다. launcher는 기본적으로 자신의 실행 파일과 같은 디렉터리에서 autobricks-vpn 동적 라이브러리를 찾습니다.

```text
Linux
target/debug/vpn-server
target/debug/vpn-client
target/debug/libautobricks_vpn.so

macOS
target/debug/vpn-server
target/debug/vpn-client
target/debug/libautobricks_vpn.dylib

Windows
target/debug/vpn-client.exe
target/debug/autobricks_vpn.dll
target/debug/wintun.dll
```

라이브러리를 다른 위치에 배치한 경우 `AUTOBRICKS_VPN_LIBRARY`에 전체 경로를 지정할 수 있습니다. wolfSSL 자체도 운영체제의 dynamic loader가 찾을 수 있는 경로에 설치되어 있어야 합니다.

```sh
AUTOBRICKS_VPN_LIBRARY=/opt/autobricks/lib/libautobricks_vpn.so \
  /opt/autobricks/bin/vpn-server --config /etc/autobricks-vpn/server.ini
```

서버는 Linux와 macOS만 지원합니다. Windows는 클라이언트만 지원하며 Wintun driver와 `wintun.dll`이 필요합니다. wolfSSL Windows 빌드 경로를 지정하고 Wintun DLL을 실행 파일 옆에 둔 뒤 실행합니다.

```powershell
$env:WOLFSSL_PREFIX = "C:\wolfssl"
$env:WINTUN_DLL = "C:\path\to\wintun.dll"
cargo build --bin vpn-client
```

Windows TUN adapter는 `wintun` crate로 생성하며 관리자 권한이 필요합니다. `netsh`와 `route`로 IPv4 주소 및 VPN route를 자동 설정합니다.

## API

실제 서버와 클라이언트 구현은 각각 `src/server.rs`, `src/client.rs`에 있으며 `src/lib.rs`가 다음 C ABI 함수를 export합니다. 공개 선언은 `include/autobricks_vpn.h`에 있습니다.

```c
int autobricks_vpn_server_run(const char *config_path);
int autobricks_vpn_client_run(const char *config_path);
```

설정 파일 경로는 필수이며 launcher의 `-c` 또는 `--config` 옵션으로 전달합니다. `--config=/path/to/config.ini` 형식도 지원하며 `-h` 또는 `--help`로 사용법을 확인할 수 있습니다. C API에서도 `config_path`가 `NULL`, 빈 문자열 또는 올바른 UTF-8 경로가 아니면 상태 `2`로 거부합니다. 정상 종료는 `0`, 설정 또는 실행 오류는 `1`, 격리된 panic은 `3`, 지원하지 않는 운영체제의 서버 호출은 `4`를 반환합니다.

`vpn-server`와 `vpn-client` 실행 파일에는 VPN 구현이 들어 있지 않습니다. Linux/macOS에서는 `dlopen`/`dlsym`, Windows에서는 `LoadLibraryW`/`GetProcAddress`로 동적 라이브러리를 열고 위 API를 호출하는 launcher입니다. 따라서 실행하려면 해당 운영체제용 autobricks-vpn 동적 라이브러리가 반드시 필요합니다. wolfSSL은 동적 라이브러리 내부에서 Rust FFI로 호출합니다.

서버는 unconnected UDP socket을 유지하며 최대 64개의 client별 DTLS session을 관리합니다. 각 session은 client의 UDP peer, 인증서 fingerprint, 고정 VPN IP를 가지고, TUN packet의 목적지 IP에 따라 해당 client로 전달합니다. 서버와 클라이언트 실행 파일이 운영체제별 TUN 생성, IPv4 주소, MTU 및 VPN 대역 route 설정을 수행합니다.

인증된 동시 세션 수는 `server.ini`의 `max_clients`로 설정합니다. 기본값은 64이고 현재 허용 범위는 1~1024입니다. 인증 전 handshake는 `max_pending_handshakes`(기본값 16, 허용 범위 1~256)로 별도 제한하며, 같은 출발지 IP에는 최대 2개만 허용하고 10초 안에 완료되지 않은 handshake는 제거합니다. 한도가 찬 경우 가장 오래된 미인증 handshake를 교체하므로 미인증 패킷이 인증된 세션 자리를 점유하지 않습니다.

활성 세션은 트래픽 유무와 관계없이 `max_session_lifetime` 이후 제거되며 기본값은 3600초, 허용 범위는 60~604800초입니다. 클라이언트가 다시 연결할 때 전체 certificate 인증과 새 key 협상을 수행하므로 장기 세션의 인증 상태가 무기한 유지되지 않습니다.

서버는 `config_reload_interval`마다 설정 파일의 `[client]` fingerprint 매핑을 다시 읽습니다. 기본값은 30초이고 허용 범위는 5~3600초입니다. 삭제되거나 변경된 binding의 활성 세션은 즉시 제거하며, 새 DTLS acceptor도 다시 만들어 갱신된 서버 인증서·개인키·CA 파일을 이후 handshake에 반영합니다. reload 검증이 실패하면 기존 정상 설정과 세션을 유지합니다.

## Example

```sh
sudo ./target/debug/vpn-server --config server.ini
sudo ./target/debug/vpn-client --config client.ini
```

Ubuntu 서버가 `10.10.254.1`에서 실행 중이면 macOS client 설정의 `server_address`를 `10.10.254.1`로 지정하고 client를 실행합니다.

디버깅 시 client 로그의 `[client] sending ClientHello` 다음에 `[client] DTLS handshake complete`가 표시되는지 확인합니다. handshake가 완료되지 않으면 서버/클라이언트가 같은 UDP port에 연결되어 있는지와 host firewall을 확인합니다. 정상 운용 시에는 packet별 로그를 출력하지 않습니다.

서버와 클라이언트 설정은 각각 `server.ini`, `client.ini`의 `[server]`, `[client]` 섹션에서 관리합니다. VPN 바이너리에서는 `ca_file`이 필수이며 누락되거나 빈 값이면 시작을 거부합니다. 서버는 client certificate chain을, 클라이언트는 server certificate chain을 해당 CA로 검증합니다. 서버와 클라이언트는 시작 시 TUN IPv4 주소와 VPN 대역 route를 자동 설정합니다. macOS의 `ifconfig`/`route`, Linux의 `ip` 명령을 사용하므로 root 권한이 필요할 수 있습니다.

개인키 경로는 일반 파일이어야 합니다. Linux와 macOS에서는 소유자 외 group/other 권한이 설정된 개인키를 거부하므로 `chmod 600 certs/server-key.pem`과 같이 보호해야 합니다. Windows에서는 일반 파일 여부를 검사하며, 키 파일 ACL은 운영체제 관리 도구로 실행 계정만 접근할 수 있게 설정해야 합니다.

클라이언트의 `keepalive_interval`은 DTLS 세션과 UDP/NAT 매핑을 유지하기 위해 암호화된 control packet을 보내는 주기(초)입니다. 5~90초 범위만 허용하며 기본값은 30초입니다. keepalive는 새로운 handshake를 반복하지 않고 현재 DTLS 세션의 활동 시간만 갱신합니다.

서버의 keepalive 응답은 control packet 전체 길이가 기록된 경우에만 성공으로 처리합니다. 0바이트 또는 partial DTLS write는 손상된 datagram을 정상 응답으로 간주하지 않고 해당 세션 오류로 처리합니다.

클라이언트의 `verify_server_san_ip` 기본값은 `true`입니다. 활성화하면 CA chain 검증뿐 아니라 접속한 `server_address`가 서버 인증서의 SAN IP 항목과 일치해야 DTLS handshake를 승인합니다. 특수한 테스트 환경에서는 `false`로 끌 수 있지만 운영 환경에서는 활성화를 권장합니다.

서버는 keepalive에 암호화된 응답을 보내며, 클라이언트는 세 주기 동안 서버 응답이 없거나 DTLS/UDP 오류가 발생하면 TUN 설정을 유지한 채 새 UDP 소켓과 DTLS 세션을 생성합니다. 재연결은 고정 3초 간격으로 시도합니다.

DTLS handshake는 wolfSSL이 알려주는 현재 재전송 시간을 `poll` deadline에 반영합니다. handshake datagram이 유실되면 클라이언트와 서버가 `wolfSSL_dtls_got_timeout()`을 호출해 필요한 flight를 재전송하며, 클라이언트 handshake의 전체 제한 시간은 30초입니다.

TUN MTU는 IPv4 최소 MTU와 내부 packet buffer를 고려해 576~1500 범위만 허용합니다. 범위를 벗어난 설정은 DTLS context 또는 TUN을 만들기 전에 오류로 거부하며, macOS의 4바이트 utun 헤더 추가 경로에서도 버퍼 길이를 다시 검사합니다.

Linux와 macOS에서 TUN 생성 도중 `ioctl`, `connect` 또는 `getsockopt`가 실패하면 열린 파일 디스크립터를 즉시 닫고 원래 운영체제 오류를 반환합니다.

서버 실행 중 TUN I/O의 `WouldBlock`과 `Interrupted`는 재시도하고 `ENOBUFS`는 해당 packet만 폐기합니다. `EBADF`, `ENODEV`, poll의 `POLLNVAL`/`POLLERR`/`POLLHUP` 및 분류되지 않은 TUN 오류는 영구 장애로 취급해 서버를 종료하므로 손상된 device에서 CPU와 오류 로그를 무한 소비하지 않습니다.

Windows 클라이언트는 Wintun session을 일반 파일 디스크립터로 취급하지 않습니다. nonblocking UDP socket과 Wintun receive queue를 함께 확인하는 Windows 전용 루프를 사용하며, Wintun session 종료는 crate의 RAII 처리에 맡깁니다.

서버는 시작할 때 인증서와 wolfSSL 설정을 먼저 검증합니다. 운영 중 발생하는 개별 client의 DTLS 생성, handshake, 인증서, read/write 및 keepalive 오류는 해당 세션에만 격리하며 다른 client와 서버 event loop는 계속 실행합니다. 잘못된 client packet을 TUN에 쓰지 못한 경우에도 해당 packet만 폐기합니다.

서버는 알 수 없는 peer의 첫 ClientHello에 대해 wolfSSL의 stateless DTLS cookie 교환을 먼저 수행합니다. 서버 시작 시 생성한 32바이트 cookie secret을 모든 stateless acceptor가 공유하므로 acceptor 교체 중에도 이미 발급한 cookie를 검증할 수 있습니다. 올바른 cookie가 돌아온 뒤에만 pending handshake 세션과 client 제한 슬롯을 할당하므로, 위조된 출발지 주소를 이용한 handshake 자원 고갈을 줄입니다.

동일한 client 인증서가 새 UDP peer에서 다시 인증되면 새 세션을 활성화한 뒤 같은 VPN IP를 사용하던 이전 세션을 즉시 제거합니다. 따라서 재연결 이후 outbound packet이 오래된 NAT endpoint로 전달되거나 하나의 할당 IP에 여러 활성 세션이 남지 않습니다.

복호화한 tunnel payload는 IPv4 version, IHL과 total length가 실제 datagram 길이와 일치하는지 검증한 뒤에만 TUN으로 전달합니다. 서버는 이 구조 검증에 더해 packet source가 인증서에 할당된 VPN IP와 같은지도 확인하므로 client의 source spoofing과 malformed packet 주입을 차단합니다.

클라이언트별 DTLS 처리와 클라이언트 연결 루프는 panic gate로 보호합니다. unwind 가능한 Rust panic은 `io::Error`로 변환되어 서버에서는 해당 세션만 제거되고, 클라이언트에서는 정상 재연결 절차로 넘어갑니다. abort, 운영체제 signal 및 FFI 내부의 메모리 오류는 panic gate의 복구 범위가 아닙니다.

DTLS callback의 I/O context는 `Dtls`가 `Box`로 직접 소유합니다. 외부 참조의 raw pointer를 보관하지 않으며, wolfSSL session을 해제한 뒤 I/O context를 해제합니다. 서버의 암호화 datagram queue도 `Dtls::push_incoming()`을 통해서만 접근합니다.

`server.ini`의 `vpn_network = 10.8.1.0/24`는 VPN 내부 주소 풀, `vpn_address = 10.8.1.1`은 서버 TUN 주소를 의미합니다. 클라이언트의 `dns_server = 10.8.1.1`은 `force_dns = true`일 때 운영체제에 강제로 적용할 VPN 내부 DNS 주소입니다.

`server.ini`의 `[client]` 섹션에서는 인증서 SHA-256 fingerprint에 VPN IP를 고정할 수 있습니다. 이 섹션에 매핑을 하나라도 넣으면 등록되지 않은 인증서는 서버가 거부합니다.

서버는 TUN을 생성하기 전에 모든 client binding을 검증합니다. VPN network는 host bit가 없는 canonical CIDR이어야 하며, client IP는 해당 network 안에 있고 서버 IP와 달라야 합니다. 중복 IP, 중복 fingerprint, 잘못된 IP 및 64자리 SHA-256 형식이 아닌 fingerprint가 있으면 서버 시작을 중단합니다.

`verify_client_san_ip`의 기본값은 `false`입니다. `true`로 설정하면 fingerprint에 연결된 VPN IP가 client 인증서의 Subject Alternative Name에 `IP Address`로 포함되어 있어야 세션을 승인합니다. 이 검사를 사용하려면 wolfSSL이 IP alternative name 지원을 포함해 빌드되어 있어야 합니다.

```ini
[client]
10.8.1.2 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
10.8.1.3 = fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

fingerprint는 `:`가 있어도 되지만 서버가 내부적으로 정규화합니다. fingerprint 확인은 다음처럼 할 수 있습니다.

```sh
openssl x509 -in client-cert.pem -noout -fingerprint -sha256
```

서버는 `10.8.1.2` 목적지 packet을 첫 번째 client session으로, `10.8.1.3` 목적지 packet을 두 번째 client session으로 보냅니다. `client.ini`의 `vpn_address`, `vpn_gateway`, `vpn_network`로 client TUN 주소와 route를 설정합니다.

`allow_broadcast`와 `allow_multicast`는 기본값이 `false`입니다. 허용하면 서버 TUN에서 나온 해당 packet을 모든 인증 client에 전달하고 client에서 들어온 packet도 TUN에 전달합니다. 비활성화된 종류는 양방향 모두 폐기합니다.

서버는 인증된 client의 연결과 해지만 syslog `local0.info`로 기록합니다. 해지 로그에는 세션 유지 시간, VPN IPv4 payload 기준 송수신 byte·packet 수와 종료 사유가 포함됩니다. keepalive, DTLS handshake 및 UDP/IP/DTLS header는 사용량에서 제외합니다. 설치 시 `packaging/rsyslog/30-autobricks-vpn.conf`를 `/etc/rsyslog.d/`에 배치하면 `/var/log/autobricks-vpn.log`로 저장되며 packet별 로그는 남기지 않습니다.

같은 외부 IP에서 유효한 DTLS cookie를 반환한 handshake가 rolling 1분 동안 30회에 도달하면 해당 IP를 10분간 차단합니다. ban과 시도 이력은 메모리에만 저장되어 서버 재시작 시 초기화되며, 10분이 지나면 자동 허용됩니다.

Linux 서버는 시작할 때 내부에서 `sysctl`과 `iptables`를 실행해 IPv4 forwarding과 client 간 전달 규칙을 설정합니다. 정상 종료 시 `autobricks-vpn-client-forward`로 표시한 전용 iptables 규칙만 제거합니다. `ip_forward`는 Docker나 다른 네트워크 서비스도 공유하는 전역 상태이므로 서버 종료 시 이전 값으로 강제 복원하지 않습니다. 비정상 종료로 전용 규칙이 남더라도 다음 시작 시 같은 comment, interface와 network에 일치하는 규칙을 제거한 뒤 하나만 다시 등록합니다.

클라이언트의 `force_dns = true`는 모든 DNS 질의를 `dns_server`로 강제합니다. Linux는 TUN link에 `resolvectl`의 `~.` route를 설정하고, macOS는 활성 network service들의 DNS를 교체하며, Windows는 전체 namespace에 NRPT 규칙을 추가합니다. 정상 종료 시 이전 설정을 복구하거나 VPN 전용 규칙을 제거합니다. VPN 내부 전용 정책이므로 지정한 DNS가 외부 이름을 해석하지 못해도 fallback DNS를 사용하지 않습니다.

`crl_file`을 지정하면 서버와 클라이언트 모두 handshake 전에 CRL을 로드하고 peer certificate 폐기를 검사합니다. `ocsp_enabled = true`이면 인증서 AIA의 OCSP URL을 사용하며, `ocsp_url`을 지정하면 해당 URL을 override하고 자동으로 OCSP를 활성화합니다. 기능을 요청했는데 wolfSSL이 CRL/OCSP 지원 없이 빌드된 경우에는 검사를 생략하지 않고 시작을 거부합니다. revoked 상태 또는 OCSP 검증·통신 실패는 handshake 실패로 처리됩니다.

이 프로젝트는 VPN 내부 통신 전용입니다. 외부 LAN이나 인터넷으로 트래픽을 전달하지 않으며 NAT/MASQUERADE와 default route 변경은 지원 범위에 포함하지 않습니다.

예제는 TUN과 DTLS 사이에서 IP packet을 양방향 전달합니다. macOS에서는 지정한 이름을 무시하고 다음 사용 가능한 `utunN`을 생성합니다. Linux에서는 지정한 TUN 이름을 사용합니다. 예제 설정은 중첩 tunnel의 fragmentation을 줄이기 위해 서버와 클라이언트 TUN MTU를 모두 1350으로 설정합니다. production 환경에서는 서버 인증서 검증 정책, 클라이언트 인증서 검증, replay 방지, 경로 MTU 탐색, 권한 분리와 키 보관을 강화해야 합니다.
