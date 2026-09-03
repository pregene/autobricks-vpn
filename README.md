# autobricks-vpn

wolfSSL 기반 DTLS 1.3 VPN transport shared library와 서버/클라이언트 예제입니다.

## Build

Rust crate와 `vpn-server`, `vpn-client` 바이너리를 Cargo로 빌드합니다.

```sh
brew install wolfssl
cargo build
```

wolfSSL이 `WOLFSSL_DTLS13`으로 빌드된 경우 DTLS 1.3 method를 사용합니다. 해당 옵션이 없는 배포 패키지에서는 빌드 검증을 위해 DTLS 1.2 method로 fallback하므로, production DTLS 1.3 배포에는 DTLS 1.3이 활성화된 wolfSSL을 직접 빌드해 링크해야 합니다.

Linux에서는 wolfSSL 개발 패키지를 설치한 뒤 `WOLFSSL_PREFIX=/path/to/wolfssl cargo build`를 실행합니다. macOS에서는 `target/debug/libautobricks_vpn.dylib`, Linux에서는 `target/debug/libautobricks_vpn.so`가 생성됩니다.

Windows는 Wintun driver와 `wintun.dll`이 필요합니다. wolfSSL Windows 빌드 경로를 지정하고 Wintun DLL을 실행 파일 옆에 둔 뒤 실행합니다.

```powershell
$env:WOLFSSL_PREFIX = "C:\wolfssl"
$env:WINTUN_DLL = "C:\path\to\wintun.dll"
cargo build
```

Windows TUN adapter는 `wintun` crate로 생성하며 관리자 권한이 필요합니다. `netsh`와 `route`로 IPv4 주소 및 VPN route를 자동 설정합니다.

## API

Rust API는 `src/lib.rs`에 있으며 wolfSSL은 Rust FFI로 호출합니다. `vpn-server`와 `vpn-client`는 Cargo binary target입니다.

서버는 unconnected UDP socket을 유지하며 최대 64개의 client별 DTLS session을 관리합니다. 각 session은 client의 UDP peer, 인증서 fingerprint, 고정 VPN IP를 가지고, TUN packet의 목적지 IP에 따라 해당 client로 전달합니다. 실제 TUN/TAP 인터페이스 연결과 라우팅은 운영체제별 권한 및 네트워크 정책에 따라 별도 구현해야 합니다.

동시 세션 수는 `server.ini`의 `max_clients`로 설정합니다. 기본값은 64이고 현재 허용 범위는 1~1024입니다. 값만큼 session table을 시작 시 할당합니다.

## Example

```sh
sudo ./target/debug/vpn-server server.ini
sudo ./target/debug/vpn-client client.ini
```

Ubuntu 서버가 `10.10.254.1`에서 실행 중이면 macOS client 설정의 `server_address`를 `10.10.254.1`로 지정하고 client를 실행합니다.

디버깅 시 client 로그의 `[client] sending ClientHello` 다음에 `[client] DTLS handshake complete`가 표시되는지 확인합니다. handshake가 완료되지 않으면 서버/클라이언트가 같은 UDP port에 연결되어 있는지와 host firewall을 확인합니다. 정상 운용 시에는 packet별 로그를 출력하지 않습니다.

서버와 클라이언트 설정은 각각 `server.ini`, `client.ini`의 `[server]`, `[client]` 섹션에서 관리합니다. `ca_file`을 지정하면 client certificate 검증을 켭니다. 서버와 클라이언트는 시작 시 TUN IPv4 주소와 VPN 대역 route를 자동 설정합니다. macOS의 `ifconfig`/`route`, Linux의 `ip` 명령을 사용하므로 root 권한이 필요할 수 있습니다.

`server.ini`의 `vpn_network = 10.8.1.0/24`는 VPN 내부 주소 풀, `vpn_address = 10.8.1.1`은 서버 TUN 주소를 의미합니다. `dns_server = 10.8.1.1`은 클라이언트가 사용할 DNS 주소 정책이며, `8.8.8.8`처럼 외부 DNS 주소도 지정할 수 있습니다. 다만 현재 값은 정책으로 파싱하고 출력하는 단계이며, 실제 TUN IP 설정과 DHCP/DNS push, 클라이언트 DNS 강제 적용은 아직 OS별 네트워크 설정 명령이 필요합니다.

`server.ini`의 `[client]` 섹션에서는 인증서 SHA-256 fingerprint에 VPN IP를 고정할 수 있습니다. 이 섹션에 매핑을 하나라도 넣으면 등록되지 않은 인증서는 서버가 거부합니다.

```ini
[client]
10.8.1.2 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
10.8.1.3 = fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

fingerprint는 `:`가 있어도 되지만 서버가 내부적으로 정규화합니다. fingerprint 확인은 다음처럼 할 수 있습니다.

```sh
openssl x509 -in client-cert.pem -noout -fingerprint -sha256
```

서버는 `10.8.1.2` 목적지 packet을 첫 번째 client session으로, `10.8.1.3` 목적지 packet을 두 번째 client session으로 보냅니다. `client.ini`의 `vpn_address`, `vpn_gateway`, `vpn_network`로 client TUN 주소와 route를 설정합니다. 서버는 Linux에서 같은 VPN 대역의 client 간 통신을 위해 IP forwarding과 `autobricks0` 간 전용 iptables 규칙을 시작 시 적용하고 정상 종료 시 제거합니다. 기존 IP forwarding 설정은 보존합니다.

클라이언트의 `client.ini`에서도 `dns_server`와 `force_dns = true`를 지정할 수 있습니다. 현재 `force_dns`는 정책을 표시하는 단계이며, 실제 DNS 강제 적용은 macOS의 `scutil`/Network Service 또는 Linux의 `resolvectl`/NetworkManager를 사용해 구현해야 합니다. DNS 주소를 `10.8.1.1`로 지정하려면 서버 측에 실제 DNS resolver가 해당 주소에서 동작해야 하며, 그렇지 않으면 `8.8.8.8` 또는 사내 DNS 주소를 사용해야 합니다.

`nat_enabled`와 `nat_interface`는 예약된 설정이며 현재 NAT를 적용하지 않습니다. VPN은 서버 및 VPN client 사이의 통신만 제공하고 외부 LAN이나 인터넷으로 향하는 MASQUERADE는 관리하지 않습니다.

예제는 TUN과 DTLS 사이에서 IP packet을 양방향 전달합니다. macOS에서는 지정한 이름을 무시하고 다음 사용 가능한 `utunN`을 생성합니다. Linux에서는 지정한 TUN 이름을 사용합니다. 예제 설정은 중첩 tunnel의 fragmentation을 줄이기 위해 서버와 클라이언트 TUN MTU를 모두 1350으로 설정합니다. production 환경에서는 서버 인증서 검증 정책, 클라이언트 인증서 검증, replay 방지, 경로 MTU 탐색, 권한 분리와 키 보관을 강화해야 합니다.
