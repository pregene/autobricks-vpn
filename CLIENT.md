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

0.8.107 Linux 클라이언트 압축 패키지는 **glibc 기반 배포판**을 대상으로 Debian Bookworm 환경(glibc 2.36)에서 빌드했다. 2026-09-22 Ubuntu 22.04.5 x86_64에서 GitHub Release 패키지로 실제 DTLS 접속, TUN 구성, 서버 ping과 SSH 연결을 확인했다. CentOS 등 다른 배포판과 Linux ARM64는 glibc 버전 및 시스템 명령 차이를 별도로 확인해야 한다.

Alpine은 musl libc를 사용하므로 이번 glibc 패키지의 지원 대상에 포함하지 않는다. 테스트 가능한 Alpine 머신에서 별도 musl 빌드와 VPN 접속을 확인한 뒤 추가 여부를 결정한다. 현재의 `vpn-client`는 같은 디렉터리의 `libautobricks_vpn.so`를 동적으로 열고, 이 라이브러리는 wolfSSL을 사용한다. 따라서 배포 시 세 파일의 로딩 경로를 함께 검증해야 한다.

Linux에서는 `/dev/net/tun` 접근 권한과 `ip` 명령이 필요하다. `force_dns = true`인 설정을 사용하면 `resolvectl`도 필요하다. 클라이언트별 인증서와 개인키가 포함된 `client.ini`는 공통 바이너리 패키지에 넣지 않고 관리 웹에서 별도로 발급한다.

## 0.8.107 클라이언트 압축 파일

[GitHub Release v0.8.107](https://github.com/pregene/autobricks-vpn/releases/tag/v0.8.107)에 `autobricks-vpn-0.8.107-{macos,linux}-{arm64,x86_64}.tar.gz` 네 파일과 `SHA256SUMS`를 첨부한다. 각 압축 파일에는 `vpn-client`, `libautobricks_vpn` 공유 라이브러리, 해당 아키텍처로 빌드한 wolfSSL 공유 라이브러리가 들어 있다. 세 파일을 같은 디렉터리에 둬야 한다. 발급한 `client.ini`는 별도로 보관하고 `--config`로 지정한다.

```sh
tar -xzf autobricks-vpn-0.8.107-linux-x86_64.tar.gz
sudo ./vpn-client --config /path/to/client.ini
```

macOS ARM64·x86_64는 이 Mac에서 `--help` 실행과 VPN 라이브러리의 wolfSSL 로딩을 확인했다. Linux ARM64·x86_64는 Docker 빌드 컨테이너에서 실행과 wolfSSL 링크를 확인했다. 이 중 Linux x86_64 Release 패키지는 Ubuntu 22.04.5에서 실제 VPN 접속과 터널 통신까지 확인했다. Linux ARM64 패키지의 실제 장비 접속은 아직 확인하지 않았다. Release에서 받은 압축 파일과 `SHA256SUMS`를 같은 폴더에 놓고 `shasum -a 256 -c SHA256SUMS`로 체크섬을 확인한다.

## Windows 클라이언트 상태

Windows는 클라이언트만 개발·지원한다. x64/MSVC에서 wolfSSL DLL을 연결한 클라이언트와 VPN DLL의 실제 빌드 및 단위 테스트를 확인했다. `build.ps1 -Test`로 재현할 수 있다. Windows UDP 수신 준비는 `src/windows/socket.rs`의 WSAPoll을 사용한다. 1바이트 UDP peek가 Windows에서 오류 10040을 발생시키던 문제를 수정했다.

필요한 DLL은 빌드 스크립트가 실행 파일 옆에 배치한다. 관리자 권한 접속·재접속·경로와 DNS 복구는 빌드 검사와 구분한다. 실행 절차는 [WINDOWS.md](WINDOWS.md), 실제 접속 결과는 [RESULT.md](RESULT.md)에 기록한다. [GitHub Release v0.8.107](https://github.com/pregene/autobricks-vpn/releases/tag/v0.8.107)에 Windows x64 Release 빌드 `autobricks-vpn-0.8.107-windows-x86_64.zip`을 추가했다. ZIP에는 클라이언트 EXE, VPN·wolfSSL·Wintun DLL, 라이선스와 소스 스냅샷이 포함되며 인증서·개인키·INI는 포함하지 않는다.
