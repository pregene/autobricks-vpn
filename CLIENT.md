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
