# VPN 클라이언트 코드 구성

클라이언트는 DTLS 세션 하나를 사용한다. 서버의 세션 검색·세션별 큐는 없고, 아래 네 큐와 여섯 실행 스레드로 패킷을 전달한다.

| 스레드 | 파일 | 입력 → 출력 |
|---|---|---|
| UDP Read Thread | `src/client/udp_read.rs` | UDP 소켓 → `encrypted_rx` |
| Decrypt Worker Thread | `src/client/decrypt.rs` | `encrypted_rx` → 단일 `WOLFSSL*` → `tun_write` |
| TUN Write Thread | `src/client/tun_write.rs` | `tun_write` → TUN |
| TUN Read Thread | `src/client/tun_read.rs` | TUN → `raw_tx` |
| Encrypt Worker Thread | `src/client/encrypt.rs` | `raw_tx` → 단일 `WOLFSSL*` → `enc_tx` |
| UDP Write Thread | `src/client/udp_write.rs` | `enc_tx` → UDP 소켓 |

`src/client/queues.rs`가 네 큐를 생성·닫는다. `src/client/mod.rs`는 연결 설정, 스레드 시작·종료 및 keepalive를 담당한다. 큐 구현과 조건 변수는 `src/base/queue.rs`, 작업 스레드의 공통 종료 동작은 `src/base/worker.rs`에 있다.

UDP 수신 큐의 소비자는 Decrypt Worker 하나뿐이다. 워커가 꺼낸 데이터그램은 `DtlsIo.incoming`에 넣고 `wolfSSL_read()`를 호출하며, wolfSSL 수신 콜백은 이 내부 입력에서만 읽는다. `WANT_READ`는 다음 수신 데이터그램을 기다리고, `WANT_WRITE`는 UDP 입출력 진행 신호 뒤 재시도한다. 실제 DTLS 오류는 별도로 보고한다.

암호화할 평문은 `raw_tx`의 맨 앞에 유지한다. `wolfSSL_write()`가 `WANT_READ` 또는 `WANT_WRITE`를 반환하면 같은 평문을 진행 신호 뒤 다시 시도한다. 암호문은 `enc_tx`를 거쳐 UDP Writer가 전송하며, 소켓 `WouldBlock`이면 앞 데이터그램을 제거하지 않고 쓰기 가능 이벤트를 기다린다. TUN Writer도 `WouldBlock`에서 앞 패킷을 유지한다.
Keepalive도 Main Thread가 `raw_tx`에 넣으며, Encrypt Worker만 `wolfSSL_write()`를 호출한다.

이 구조의 macOS release 빌드와 단위 테스트는 검증했지만, 실제 VPN 트래픽 및 성능은 클라이언트를 새 바이너리로 실행한 후 별도로 확인해야 한다.
