# VPN 서버 코드 구성

서버 코드는 아래 파일 경계에 맞춰 정리한다. Main Thread가 UDP Read Thread이며, 별도의 UDP Read Thread를 생성하지 않는다.

## 스레드와 파일

| 스레드 | 파일 위치 | 목적 |
|---|---|---|
| Main Thread (UDP Read) | `src/server/udp_read.rs` | UDP 소켓에서 패킷과 송신자 주소를 읽어 `udp_rx_queue`에 넣는다. |
| TUN Read Thread | `src/server/tun_read.rs` | TUN에서 패킷을 읽어 `tun_read_queue`에 넣는다. |
| Decrypt Worker Thread | `src/server/decrypt.rs` | `udp_rx_queue`의 패킷을 해당 세션의 DTLS로 복호화하고, 출력이 있으면 `tun_write_queue`에 넣는다. |
| TUN Write Thread | `src/server/tun_write.rs` | `tun_write_queue`의 패킷을 TUN에 쓴다. |
| Encrypt Worker Thread | `src/server/encrypt.rs` | `tun_read_queue`의 패킷을 목적지 세션에 배정하고 암호화한다. 재시도가 필요한 평문은 세션의 `raw_tx_queue`에 유지하며, 암호문은 `enc_tx_queue`에 넣는다. |
| UDP Write Thread | `src/server/udp_write.rs` | 각 세션의 `enc_tx_queue`에서 전송 가능한 패킷을 꺼내 UDP 소켓으로 보낸다. 한 세션이 막혀도 다른 세션을 확인한다. |
| Session Control Thread | `src/server/control.rs` | 핸드셰이크 재전송 타이머, 세션 만료, 설정 재로드, 웹 제어 명령을 처리한다. |

## 큐와 공통 코드

| 파일 위치 | 목적 |
|---|---|
| `src/base/queue.rs` | 용량을 지정하는 공용 FIFO 큐 구현. `Mutex`·`Condvar`로 대기와 깨우기를 처리한다. |
| `src/base/worker.rs` | 큐를 기다리는 작업 스레드의 공통 실행·종료 동작을 제공한다. |
| `src/server/queues.rs` | 공용 `udp_rx_queue`, `tun_write_queue`, `tun_read_queue`의 소유·생성을 관리한다. |
| `src/server/session.rs` | 세션의 DTLS 상태와 세션별 `raw_tx_queue`, `enc_tx_queue`를 관리한다. |

공용 패킷 큐는 3개, 세션별 패킷 큐는 세션마다 2개다. 공용 UDP 송신 큐는 두지 않는다.
`raw_tx_queue`의 앞 패킷은 DTLS 쓰기가 `WANT_READ`/`WANT_WRITE`일 때 제거하지 않고, 진행 이벤트가 오면 같은 패킷부터 다시 시도한다. `enc_tx_queue`의 UDP 송신도 `WouldBlock`이면 앞 패킷을 유지한다.

## 진입점과 하위 기능

| 파일 위치 | 목적 |
|---|---|
| `src/bin/vpn-server.rs` | 서버 실행 파일의 진입점. |
| `src/bin/common/mod.rs` | 실행 파일의 인자 처리와 VPN 라이브러리 로딩. |
| `src/server.rs` | 서버 초기화, 스레드·큐 연결 및 종료 순서만 조정한다. |
| `src/server/socket.rs` | UDP 수신·송신과 소켓 준비 상태 확인에 쓰는 공통 함수. |
| `src/lib.rs` | wolfSSL/DTLS 및 TUN의 공용 래퍼와 FFI 진입점. |
| `src/linux/mod.rs` | Linux TUN·소켓 플랫폼 구현. |
| `src/macos/mod.rs` | macOS TUN·소켓 플랫폼 구현. |

서버 수신 경로: `Main Thread → udp_rx_queue → Decrypt Worker Thread → tun_write_queue → TUN Write Thread`.

서버 송신 경로: `TUN Read Thread → tun_read_queue → Encrypt Worker Thread → 세션별 raw_tx_queue/enc_tx_queue → UDP Write Thread`.

Session Control Thread는 제어 소켓 입력, 세션 변경 알림, 다음 세션 타이머 또는 설정 재로드 시점에 깨어난다. 연결 상태 전달을 위한 고정 주기 폴링은 사용하지 않는다.
