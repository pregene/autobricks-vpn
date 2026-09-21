# autobricks-vpn

wolfSSL 기반 DTLS 1.3 VPN transport shared library와 서버/클라이언트 예제입니다.

```text
Autobricks VPN 0.8.107
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
| 선택적 로그인 | 등록 항목에 ID·암호가 있으면 DTLS 인증 후 로그인까지 확인; 없으면 인증서만 확인 |
| SAN 검증 | 서버 SAN IP 검증, 선택적인 클라이언트 SAN IP 검증 |
| 인증서 폐기 | CRL 및 OCSP(AIA URL 또는 override URL), 실패 시 연결 거부 |
| 세션 관리 | keepalive, idle timeout, 최대 세션 수명, 고정 3초 재연결, 재인증 |
| 설정 갱신 | 서버의 client binding 주기적 reload 및 웹의 즉시 RELOAD 요청 |
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

## 서버·클라이언트 패킷 처리 구성

### 클라이언트

클라이언트는 DTLS 세션 하나와 6개 작업 스레드를 사용합니다. UDP Read는 수신 데이터그램을 `encrypted_rx`에 넣고, Decrypt worker가 이를 꺼내 `wolfSSL_inject()`와 `wolfSSL_read()`를 호출합니다. 따라서 `encrypted_rx`는 `inject()`를 대신하는 큐가 아니라 두 스레드 사이의 전달 큐입니다. 네 큐의 용량은 각각 512패킷입니다. 파일별 역할은 [CLIENT.md](CLIENT.md)에 정리했습니다.

```mermaid
flowchart LR
    subgraph CRX["수신: 서버 → 클라이언트 TUN"]
        direction LR
        CS1["VPN 서버"] --> CR1["UDP Read"] --> CQ1["encrypted_rx<br/>512"] --> CD["Decrypt worker<br/>inject + read"] --> CQ2["tun_write<br/>512"] --> CW1["TUN Write"] --> CT1["로컬 TUN"]
    end
    subgraph CTX["송신: 클라이언트 TUN → 서버"]
        direction LR
        CT2["로컬 TUN"] --> CR2["TUN Read"] --> CQ3["raw_tx<br/>512"] --> CE["Encrypt worker<br/>DTLS write"] --> CQ4["enc_tx<br/>512"] --> CW2["UDP Write"] --> CS2["VPN 서버"]
    end
```

메인 스레드는 설정 로드, TUN·DNS 설정, UDP 연결과 DTLS handshake를 수행한 뒤 작업 스레드를 시작합니다. 연결 중에는 keepalive를 `raw_tx`에 넣고 서버 응답을 감시하며, 연결이 끊기면 재접속합니다. Decrypt와 Encrypt worker는 같은 `SynchronizedDtls` 세션의 wolfSSL 호출을 직렬화합니다.

### 서버

서버는 메인 스레드의 UDP Read와 Decrypt, TUN Read, Encrypt, UDP Write, Session Control 작업 스레드로 구성됩니다. 수신 경로의 Decrypt worker가 peer별 DTLS handshake·복호화·출발지 VPN IP 검사를 처리하고 TUN에 직접 기록합니다. 송신 경로의 Encrypt worker는 목적지 VPN IP로 세션을 찾아 암호화하며, UDP Write worker가 세션별 암호문 큐를 전송합니다.

```mermaid
flowchart LR
    subgraph SRX["수신: 클라이언트 → 서버 TUN"]
        direction LR
        SC1["VPN 클라이언트"] --> SR1["UDP Read<br/>메인 스레드"] --> SQ1["udp_rx_queue<br/>4096"] --> SD["Decrypt worker<br/>handshake + decrypt + IP 검사"] --> STW["TUN 직접 기록"] --> ST1["서버 TUN"]
    end
    subgraph STX["송신: 서버 TUN → 클라이언트"]
        direction LR
        ST2["서버 TUN"] --> SR2["TUN Read"] --> SQ2["tun_read_queue<br/>4096"] --> SE["Encrypt worker<br/>목적지 세션 선택"] --> SQ3["세션별 raw_tx_queue<br/>512"] --> SDTLS["DTLS write<br/>Encrypt worker"] --> SQ4["세션별 enc_tx_queue<br/>512"] --> SW["UDP Write"] --> SC2["VPN 클라이언트"]
    end
```

각 세션은 peer 주소, 할당된 VPN IP, 인증서 fingerprint, `SynchronizedDtls`, 평문 `raw_tx_queue`와 암호문 `enc_tx_queue`를 보유합니다. Session Control worker는 세션 만료·DTLS 재전송·설정 및 인증서 재로드를 처리하고 Unix control socket의 `WATCH`·`DISCONNECT`·`RELOAD` 명령을 받습니다. Express 운영 화면은 이 소켓의 상태 변경을 SSE로 전달합니다.

```mermaid
flowchart LR
    CFG["server.ini · 인증서 · 클라이언트 binding"] --> CTRL["Session Control worker<br/>만료 · 재전송 · reload"] --> SESS["공유 Session 목록"]
    WEB["Express 운영 화면"] <-->|Unix socket| CTRL
```

`Queue<T>`는 용량이 찼을 때 가장 오래된 패킷을 제거하고 소비자를 깨웁니다. 종료할 때는 큐를 닫아 대기 중인 작업을 깨웁니다. 서버의 두 공용 큐는 각각 4096패킷, 세션별 송신 큐는 각각 512패킷입니다. 방향별 overflow 수는 클라이언트 연결 또는 서버 종료 시 로그로 출력합니다. TCP 신뢰성과 재전송은 터널 내부 TCP endpoint가 담당하며, DTLS application data 자체는 손실 패킷을 재전송하지 않습니다.

## 개발환경 구성

운영 서버는 `./build.sh`(또는 `./build.sh --release`)로 `bin/`을 만든 뒤 `./install.sh`로 설치합니다. 인증서 생성과 서비스 등록 절차는 [INSTALL.md](INSTALL.md)를 참고합니다.

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
  --enable-ip-alt-name \
  --enable-aesni --enable-intelasm --enable-sp --enable-sp-asm
make -j4
sudo make install
```

`--enable-aesni`, `--enable-intelasm`, `--enable-sp --enable-sp-asm`는 x86_64에서 AES-NI 및 SIMD 기반 암호 연산을 켭니다. 이 플래그 없이 빌드하면 wolfSSL은 순수 소프트웨어 AES로 동작해 패킷당 암복호화 비용이 눈에 띄게 커집니다. ARM64(예: Apple Silicon, AWS Graviton)에서는 대신 `--enable-armasm`을 사용합니다. 빌드 후 `grep -E "AESNI|USE_INTEL_SPEEDUP" /opt/wolfssl-autobricks/include/wolfssl/options.h`로 실제로 활성화됐는지 확인할 수 있습니다.

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

과거 결과를 포함한 성능 비교와 최적화 이력은 [PERFORMANCE.md](PERFORMANCE.md)에서 관리합니다.

## Build

VPN 구현이 들어 있는 동적 라이브러리와 이를 호출하는 `vpn-server`, `vpn-client` launcher를 Cargo로 빌드합니다.

OS 종속 packet I/O와 TUN 구현은 공통 DTLS/session 코드와 분리되어 있습니다.

| 경로 | 현재 구현 | 확장 경계 |
| --- | --- | --- |
| `src/linux/` | `/dev/net/tun`, nonblocking UDP, `poll` readiness | `io_uring` completion 및 batch I/O |
| `src/macos/` | `utun`, 4-byte protocol header, `poll` readiness | `kqueue` readiness |
| `src/windows/` | Wintun ring, nonblocking UDP 확인 | Overlapped I/O/IOCP와 Wintun read event |

공통 client/server 루프는 OS API를 직접 호출하지 않고 선택된 platform backend의 `wait_udp`, `wait_io` 및 `Tun`을 사용합니다. 따라서 이후 Linux `io_uring` 또는 Windows IOCP를 도입할 때 DTLS 인증과 session routing 코드를 별도로 복제하지 않습니다.

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

서버 구현은 `src/server.rs`와 `src/server/`, 클라이언트 구현은 `src/client/mod.rs`와 `src/client/`에 있으며 `src/lib.rs`가 다음 C ABI 함수를 export합니다. 공개 선언은 `include/autobricks_vpn.h`에 있습니다.

```c
int autobricks_vpn_server_run(const char *config_path);
int autobricks_vpn_client_run(const char *config_path);
int autobricks_vpn_client_run_with_login(const char *config_path, const char *user, const char *password);
```

서버 설정 파일 경로는 필수이며 launcher의 `-c` 또는 `--config` 옵션으로 전달합니다. 클라이언트는 `--config`를 생략하면 작업 디렉터리의 `config/client.ini`를 사용합니다. 클라이언트 로그인 정보는 `--user <ID> --pass <PASSWORD>`로 함께 전달할 수 있으며, 생략하면 서버가 로그인을 요구할 때 터미널에서 입력받습니다. 입력한 정보는 실행 중 메모리에 보관해 재접속에 사용합니다. 명령행 암호는 셸 기록과 프로세스 인자에 남을 수 있으므로 노출을 피하려면 터미널 입력을 사용합니다. `--config=/path/to/config.ini` 형식과 `-h` 또는 `--help`도 지원합니다. C API에서도 `config_path`가 `NULL`, 빈 문자열 또는 올바른 UTF-8 경로가 아니면 상태 `2`로 거부합니다. 정상 종료는 `0`, 설정 또는 실행 오류는 `1`, 격리된 panic은 `3`, 지원하지 않는 운영체제의 서버 호출은 `4`를 반환합니다.

`vpn-server`와 `vpn-client` 실행 파일에는 VPN 구현이 들어 있지 않습니다. Linux/macOS에서는 `dlopen`/`dlsym`, Windows에서는 `LoadLibraryW`/`GetProcAddress`로 동적 라이브러리를 열고 위 API를 호출하는 launcher입니다. 따라서 실행하려면 해당 운영체제용 autobricks-vpn 동적 라이브러리가 반드시 필요합니다. wolfSSL은 동적 라이브러리 내부에서 Rust FFI로 호출합니다.

서버는 unconnected UDP socket을 유지하며 최대 64개의 client별 DTLS session을 관리합니다. 각 session은 client의 UDP peer, 인증서 fingerprint, 고정 VPN IP를 가지고, TUN packet의 목적지 IP에 따라 해당 client로 전달합니다. 서버와 클라이언트 실행 파일이 운영체제별 TUN 생성, IPv4 주소, MTU 및 VPN 대역 route 설정을 수행합니다.

인증된 동시 세션 수는 `server.ini`의 `max_clients`로 설정합니다. 기본값은 64이고 현재 허용 범위는 1~1024입니다. 인증 전 handshake는 `max_pending_handshakes`(기본값 16, 허용 범위 1~256)로 별도 제한하며, 같은 출발지 IP에는 최대 2개만 허용하고 10초 안에 완료되지 않은 handshake는 제거합니다. 한도가 찬 경우 가장 오래된 미인증 handshake를 교체하므로 미인증 패킷이 인증된 세션 자리를 점유하지 않습니다.

서버의 일반 unicast 경로는 UDP peer endpoint와 VPN IP를 각각 `HashMap`으로 인덱싱해 세션을 O(1)로 찾습니다. 인증서 fingerprint도 역방향 `HashMap`으로 VPN IP를 조회합니다. 전체 세션 순회는 broadcast/multicast 전달, timeout 정리와 관리 상태 snapshot에만 사용합니다.

DTLS 쓰기가 `WouldBlock`이면 아직 전송되지 않은 내부 패킷을 세션별 송신 대기 queue에 보관합니다. queue는 세션당 최대 256패킷이며 가득 차면 가장 오래된 패킷을 제거합니다. 2초 이상 대기한 패킷은 폐기하고 한 event-loop 회차에 세션당 최대 32패킷만 처리해 한 클라이언트가 다른 세션의 송신을 독점하지 않게 합니다. 성공한 DTLS application record는 이 queue에서 재전송하지 않습니다.

활성 세션은 트래픽 유무와 관계없이 `max_session_lifetime` 이후 제거되며 기본값은 3600초, 허용 범위는 60~604800초입니다. 클라이언트가 다시 연결할 때 전체 certificate 인증과 새 key 협상을 수행하므로 장기 세션의 인증 상태가 무기한 유지되지 않습니다.

서버는 `config_reload_interval`마다 설정 파일의 `[client]` fingerprint 및 선택적 로그인 정보를 다시 읽습니다. 기본값은 30초이고 허용 범위는 5~3600초입니다. 웹에서 추가·삭제하면 `RELOAD` 제어 명령으로 즉시 반영합니다. 삭제되거나 변경된 binding 및 로그인 정보의 활성 세션은 제거하며, 새 DTLS acceptor도 다시 만듭니다. reload 검증이 실패하면 기존 정상 설정과 세션을 유지합니다. 별도 종료 메시지 없이 종료한 클라이언트는 서버에서 마지막 활동 후 300초에 연결 해제로 처리합니다. 클라이언트 쪽 23초는 서버 응답을 기다리는 시간입니다.

## Push 전 검사

필요할 때 아래 명령으로 push 전 검사를 실행합니다. 프로젝트용 wolfSSL 경로를 명시해야 하며 기본 feature는 `dtls13`입니다. panic gate 단위 테스트는 한 개씩 실행하면서 각 테스트의 시작과 검증 결과를 로그로 출력하고, 이어서 전체 테스트, Clippy와 diff 검사를 수행합니다.

```sh
WOLFSSL_PREFIX=/path/to/project-wolfssl ./scripts/pre-push-test.sh
```

다른 feature 조합이 필요하면 `AUTOBRICKS_VPN_FEATURES`로 지정합니다.

```sh
WOLFSSL_PREFIX=/path/to/project-wolfssl \
  AUTOBRICKS_VPN_FEATURES=dtls13 \
  ./scripts/pre-push-test.sh
```

## Example

```sh
sudo ./target/debug/vpn-server --config server.ini
sudo ./target/debug/vpn-client --config client.ini
```

## 성능 측정 기록

성능 측정 조건, 결과와 변경 이력은 [PERFORMANCE.md](PERFORMANCE.md)에 누적합니다. 실제 운영 endpoint는 기록하지 않습니다.

Ubuntu 서버가 `10.10.254.1`에서 실행 중이면 macOS client 설정의 `server_address`를 `10.10.254.1`로 지정하고 client를 실행합니다.

디버깅 시 client 로그의 `[client] sending ClientHello` 다음에 `[client] DTLS handshake complete`가 표시되는지 확인합니다. handshake가 완료되지 않으면 서버/클라이언트가 같은 UDP port에 연결되어 있는지와 host firewall을 확인합니다. 정상 운용 시에는 packet별 로그를 출력하지 않습니다.

서버와 클라이언트 설정은 각각 `server.ini`, `client.ini`의 `[server]`, `[client]` 섹션에서 관리합니다. `[certificate]`, `[key]`, `[ca]` PEM 섹션을 같은 INI에 넣으면 파일 경로 설정보다 우선합니다. 단일 INI에 개인키가 포함되므로 소유자 전용 파일 권한을 사용합니다. 서버의 `[ca]`는 클라이언트 인증서 검증용 Intermediate CA와 Root CA 체인을 담습니다. 서버는 client certificate chain을, 클라이언트는 server certificate chain을 해당 CA로 검증합니다. 서버와 클라이언트는 시작 시 TUN IPv4 주소와 VPN 대역 route를 자동 설정합니다. macOS의 `ifconfig`/`route`, Linux의 `ip` 명령을 사용하므로 root 권한이 필요할 수 있습니다.

### 서버 trust chain

서버는 다음과 같이 클라이언트 인증서 검증용 trust chain을 지정합니다.

```ini
[server]
certificate_file = certs/server-cert.pem
private_key_file = certs/server-key.pem
ca_file = certs/trust-chain.pem
```

`trust-chain.pem`은 서버 자신의 인증서 체인이 아니라 서버가 신뢰할 클라이언트 발급 CA 목록입니다. Intermediate CA를 사용하는 운영 환경에서는 발급 CA부터 Root CA 순서로 하나의 PEM 파일에 넣습니다.

```pem
-----BEGIN CERTIFICATE-----
Intermediate CA certificate
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
Root CA certificate
-----END CERTIFICATE-----
```

로컬 발급 구성은 Intermediate CA 개인키로 클라이언트 인증서를 서명합니다. `server.ini`에 `[root_ca]`, `[intermediate_ca]`, `[intermediate_key]` PEM 섹션을 넣으면 웹 발급 기능이 해당 내용을 우선 사용합니다. `[certificate]`는 서버 자신의 인증서이고 `[ca]`는 상대방 인증서를 검증하는 신뢰 체인입니다.

### 웹 실시간 세션 제어

VPN 서버는 `control_socket`에 Unix domain socket을 열어 로컬 관리 웹과 통신합니다. `WATCH` 구독이 연결되면 현재 세션 snapshot을 한 번 전송하고, 이후 클라이언트 연결·재연결·종료로 연결 목록이 바뀔 때만 새 snapshot을 push합니다. 브라우저에는 Express가 이 스트림을 SSE로 전달하므로 주기적인 HTTP polling을 사용하지 않습니다.

웹에서 클라이언트를 삭제하면 `server.ini`의 등록 항목을 제거하고 `RELOAD` 명령으로 VPN 서버에 즉시 반영합니다. 서버는 삭제된 클라이언트의 활성 DTLS 세션을 제거합니다. `DISCONNECT <VPN IP>` 명령은 등록을 유지한 채 활성 연결만 끊는 별도 제어 명령으로 사용할 수 있습니다.

control socket은 `server.ini`의 `control_socket`으로 지정하며 기본값은 `/var/run/autobricks-vpn.sock`입니다. 생성 권한은 `0660`이므로 VPN 서버와 웹 프로세스는 socket을 읽고 쓸 수 있는 동일한 운영 그룹으로 실행해야 합니다.

개인키 경로는 일반 파일이어야 합니다. Linux와 macOS에서는 소유자 외 group/other 권한이 설정된 개인키를 거부하므로 `chmod 600 certs/server-key.pem`과 같이 보호해야 합니다. Windows에서는 일반 파일 여부를 검사하며, 키 파일 ACL은 운영체제 관리 도구로 실행 계정만 접근할 수 있게 설정해야 합니다.

클라이언트의 `keepalive_interval`은 DTLS 세션과 UDP/NAT 매핑을 유지하기 위해 암호화된 control packet을 보내는 주기(초)입니다. 5~90초 범위만 허용하며 기본값은 30초입니다. keepalive는 새로운 handshake를 반복하지 않고 현재 DTLS 세션의 활동 시간만 갱신합니다.

서버의 keepalive 응답은 control packet 전체 길이가 기록된 경우에만 성공으로 처리합니다. 0바이트 또는 partial DTLS write는 손상된 datagram을 정상 응답으로 간주하지 않고 해당 세션 오류로 처리합니다.

클라이언트의 `verify_server_san_ip` 기본값은 `true`입니다. 활성화하면 CA chain 검증뿐 아니라 접속한 `server_address`가 서버 인증서의 SAN IP 항목과 일치해야 DTLS handshake를 승인합니다. 특수한 테스트 환경에서는 `false`로 끌 수 있지만 운영 환경에서는 활성화를 권장합니다.

서버는 keepalive에 암호화된 응답을 보냅니다. 클라이언트는 마지막 서버 활동 후 20초부터 1초 간격으로 health probe를 보내고 23초에 도달하면 TUN 설정을 유지한 채 새 UDP 소켓과 DTLS 세션을 즉시 생성합니다. 일반적인 handshake 또는 연결 오류가 발생한 경우에만 다음 시도 전 3초를 기다립니다.

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
10.8.1.3 = fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 example-user example-password
```

두 번째 항목처럼 ID와 암호를 붙이면 인증서 검증 후 로그인이 필요합니다. 둘 다 없는 항목은 인증서만 검증합니다. 로그인 정보는 서버 설정에만 저장하며 발급된 클라이언트 INI에는 넣지 않습니다.

fingerprint는 `:`가 있어도 되지만 서버가 내부적으로 정규화합니다. fingerprint 확인은 다음처럼 할 수 있습니다.

```sh
openssl x509 -in client-cert.pem -noout -fingerprint -sha256
```

서버는 `10.8.1.2` 목적지 packet을 첫 번째 client session으로, `10.8.1.3` 목적지 packet을 두 번째 client session으로 보냅니다. `client.ini`의 `vpn_address`, `vpn_gateway`, `vpn_network`로 client TUN 주소와 route를 설정합니다.

`allow_broadcast`와 `allow_multicast`는 기본값이 `false`입니다. 허용하면 서버 TUN에서 나온 해당 packet을 모든 인증 client에 전달하고 client에서 들어온 packet도 TUN에 전달합니다. 비활성화된 종류는 양방향 모두 폐기합니다.

서버는 인증된 client의 연결과 해지만 syslog `local0.info`로 기록합니다. 해지 로그에는 세션 유지 시간, VPN IPv4 payload 기준 송수신 byte·packet 수와 종료 사유가 포함됩니다. keepalive, DTLS handshake 및 UDP/IP/DTLS header는 사용량에서 제외합니다. 설치 시 `packaging/rsyslog/30-autobricks-vpn.conf`를 `/etc/rsyslog.d/`에 배치하면 `/var/log/autobricks-vpn.log`로 저장되며 packet별 로그는 남기지 않습니다.

같은 외부 IP에서 유효한 DTLS cookie를 반환한 handshake가 rolling 1분 동안 30회에 도달하면 해당 IP를 10분간 차단합니다. ban과 시도 이력은 메모리에만 저장되어 서버 재시작 시 초기화되며, 10분이 지나면 자동 허용됩니다.

Linux 서버는 시작할 때 내부에서 `sysctl`과 `iptables`를 실행해 IPv4 forwarding과 client 간 전달 규칙을 설정합니다. 같은 TUN 인터페이스에 연결된 VPN 클라이언트들은 서로 직접 전송할 수 없으므로 `net.ipv4.conf.<tun>.send_redirects=0`을 설정해 잘못된 ICMP Redirect Host 메시지를 차단합니다. 정상 종료 시 `autobricks-vpn-client-forward`로 표시한 전용 iptables 규칙만 제거합니다. `ip_forward`는 Docker나 다른 네트워크 서비스도 공유하는 전역 상태이므로 서버 종료 시 이전 값으로 강제 복원하지 않습니다. 비정상 종료로 전용 규칙이 남더라도 다음 시작 시 같은 comment, interface와 network에 일치하는 규칙을 제거한 뒤 하나만 다시 등록합니다.

클라이언트의 `force_dns = true`는 모든 DNS 질의를 `dns_server`로 강제합니다. Linux는 TUN link에 `resolvectl`의 `~.` route를 설정하고, macOS는 활성 network service들의 DNS를 교체하며, Windows는 전체 namespace에 NRPT 규칙을 추가합니다. 정상 종료 시 이전 설정을 복구하거나 VPN 전용 규칙을 제거합니다. VPN 내부 전용 정책이므로 지정한 DNS가 외부 이름을 해석하지 못해도 fallback DNS를 사용하지 않습니다.

`crl_file`을 지정하면 서버와 클라이언트 모두 handshake 전에 CRL을 로드하고 peer certificate 폐기를 검사합니다. `ocsp_enabled = true`이면 인증서 AIA의 OCSP URL을 사용하며, `ocsp_url`을 지정하면 해당 URL을 override하고 자동으로 OCSP를 활성화합니다. 기능을 요청했는데 wolfSSL이 CRL/OCSP 지원 없이 빌드된 경우에는 검사를 생략하지 않고 시작을 거부합니다. revoked 상태 또는 OCSP 검증·통신 실패는 handshake 실패로 처리됩니다.

이 프로젝트는 VPN 내부 통신 전용입니다. 외부 LAN이나 인터넷으로 트래픽을 전달하지 않으며 NAT/MASQUERADE와 default route 변경은 지원 범위에 포함하지 않습니다.

예제는 TUN과 DTLS 사이에서 IP packet을 양방향 전달합니다. macOS에서는 지정한 이름을 무시하고 다음 사용 가능한 `utunN`을 생성합니다. Linux에서는 지정한 TUN 이름을 사용합니다. 예제 설정은 중첩 tunnel의 fragmentation을 줄이기 위해 서버와 클라이언트 TUN MTU를 모두 1350으로 설정합니다. production 환경에서는 서버 인증서 검증 정책, 클라이언트 인증서 검증, replay 방지, 경로 MTU 탐색, 권한 분리와 키 보관을 강화해야 합니다.
