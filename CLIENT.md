# VPN 클라이언트 코드 구성

클라이언트는 DTLS 세션 하나를 사용한다. 서버의 세션 검색·세션별 큐는 없고, 아래 네 큐와 여섯 작업 스레드로 패킷을 전달한다. Main Thread는 연결과 작업 스레드를 관리한다.

| 스레드 | 파일 | 입력 → 출력 |
|---|---|---|
| UDP Read Thread | `src/client/udp_read.rs` | UDP 소켓 → `encrypted_rx` |
| Decrypt Worker Thread | `src/client/decrypt.rs` | `encrypted_rx` → 단일 `WOLFSSL*` → `tun_write` |
| TUN Write Thread | `src/client/tun_write.rs` | `tun_write` → TUN |
| TUN Read Thread | `src/client/tun_read.rs` | TUN → `raw_tx` |
| Encrypt Worker Thread | `src/client/encrypt.rs` | `raw_tx` → 단일 `WOLFSSL*` → `enc_tx` |
| UDP Write Thread | `src/client/udp_write.rs` | `enc_tx` → UDP 소켓 |

`src/client/queues.rs`가 용량 512인 네 큐를 생성·닫는다. `src/client/mod.rs`는 UDP 연결과 DTLS 핸드셰이크, 스레드 시작·종료, keepalive 및 재연결을 담당한다. 큐 구현과 조건 변수는 `src/base/queue.rs`, 작업 스레드의 공통 동작은 `src/base/worker.rs`에 있다.

핸드셰이크가 끝나면 DTLS의 수신 콜백을 끄고, UDP Read Thread가 받은 암호문을 `encrypted_rx`에 넣는다. Decrypt Worker만 이 큐를 소비하며, `Dtls::inject()`로 데이터그램을 전달한 뒤 `read_status()`로 평문을 꺼낸다. 남은 평문이 있으면 먼저 읽고, `WANT_READ`에서는 다음 수신 데이터그램을 기다리며, `WANT_WRITE`에서는 입출력 진행 신호 뒤 재시도한다. 복호화된 keepalive는 TUN에 쓰지 않는다.

암호화할 평문은 `raw_tx`의 맨 앞에 유지한다. DTLS 쓰기가 `WANT_READ` 또는 `WANT_WRITE`를 반환하면 같은 평문을 진행 신호 뒤 다시 시도한다. DTLS 송신 콜백이 암호문을 `enc_tx`에 넣고 UDP Write Thread가 전송한다. 소켓이나 TUN 쓰기가 `WouldBlock`이면 각 큐의 앞 패킷을 유지한다. Keepalive도 Main Thread가 `raw_tx`에 넣으며, Encrypt Worker만 DTLS 쓰기를 호출한다.

Main Thread는 서버 활동이 끊기면 상태 확인 패킷을 보내고, 응답 제한 시간이 지나면 연결을 종료해 재연결한다. 작업 스레드 오류도 Main Thread에 전달한다. 연결 종료 시 큐를 닫고 작업 스레드를 깨워 합류한 뒤, 설정한 TUN·경로·DNS 상태를 정리한다.

## Linux 클라이언트 배포 범위

0.8.107 Linux 클라이언트 압축 패키지는 **glibc 기반 배포판**을 대상으로 Debian Bookworm 환경(glibc 2.36)에서 빌드했다. Ubuntu·CentOS 등에서도 glibc 2.36 이상 여부와 시스템 명령 차이를 확인해야 한다. 배포판별 실제 VPN 접속은 아직 검증하지 않았다.

Alpine은 musl libc를 사용하므로 이번 glibc 패키지의 지원 대상에 포함하지 않는다. 테스트 가능한 Alpine 머신에서 별도 musl 빌드와 VPN 접속을 확인한 뒤 추가 여부를 결정한다. 현재의 `vpn-client`는 같은 디렉터리의 `libautobricks_vpn.so`를 동적으로 열고, 이 라이브러리는 wolfSSL을 사용한다. 따라서 배포 시 세 파일의 로딩 경로를 함께 검증해야 한다.

Linux에서는 `/dev/net/tun` 접근 권한과 `ip` 명령이 필요하다. `force_dns = true`인 설정을 사용하면 `resolvectl`도 필요하다. 클라이언트별 인증서와 개인키가 포함된 `client.ini`는 공통 바이너리 패키지에 넣지 않고 관리 웹에서 별도로 발급한다.

## 0.8.107 클라이언트 압축 파일

`client-package/`에 `autobricks-vpn-0.8.107-{macos,linux}-{arm64,x86_64}.tar.gz` 네 파일과 `SHA256SUMS`가 있다. 각 압축 파일에는 `vpn-client`, `libautobricks_vpn` 공유 라이브러리, 해당 아키텍처로 빌드한 wolfSSL 공유 라이브러리가 들어 있다. 세 파일을 같은 디렉터리에 둬야 한다. 발급한 `client.ini`는 별도로 보관하고 `--config`로 지정한다.

```sh
tar -xzf autobricks-vpn-0.8.107-linux-x86_64.tar.gz
sudo ./vpn-client --config /path/to/client.ini
```

macOS ARM64·x86_64는 이 Mac에서 `--help` 실행과 VPN 라이브러리의 wolfSSL 로딩을 확인했다. Linux ARM64·x86_64는 Docker 빌드 컨테이너에서 실행과 wolfSSL 링크를 확인했다. 이 네 압축 파일 자체를 이용한 VPN 접속 시험은 아직 하지 않았다. 압축 파일의 체크섬은 `cd client-package && shasum -a 256 -c SHA256SUMS`로 확인한다.

## Windows 클라이언트 상태

Windows용 Wintun 장치, IPv4 주소·경로·DNS 설정, DTLS 클라이언트 경로는 코드에 있다. macOS에서 `cargo check --target x86_64-pc-windows-msvc --features dtls13 --bin vpn-client --lib`가 통과했다. 이는 Rust 코드의 컴파일 검사이며, MSVC용 wolfSSL을 연결한 실행 파일 빌드나 Windows에서의 실행을 뜻하지 않는다.

Windows 패키지를 만들려면 같은 아키텍처와 MSVC ABI로 빌드한 wolfSSL 공유 라이브러리 및 Wintun DLL이 필요하다. Wintun 드라이버 설치, VPN 연결, 재접속, 경로와 DNS 복구는 실제 Windows PC 또는 VM에서 검증해야 한다. 이 Mac의 Docker는 Linux 컨테이너를 실행하므로 Wintun을 통한 Windows VPN 동작을 검증할 수 없다. 현재 Windows 배포 압축 파일은 없다.
