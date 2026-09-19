# VPN 테스트 케이스

## 서버 ↔ 클라이언트 (TC-01~TC-12)

목적: **단일 클라이언트로 VPN 서버의 연결, 송수신, 성능 및 복구 동작을 검증한다.** 병렬 TCP는 클라이언트 한 대의 연결 여러 개를 뜻한다. 클라이언트 간 통신은 이 그룹에 포함하지 않는다.

### 재현용 실행값

이 그룹은 macOS 클라이언트 `10.8.1.2`와 Ubuntu 서버 `10.8.1.1`의 터널 경로에서 실행한다. 아래 값은 실행자가 그대로 복사해 쓰는 이 테스트 그룹의 고정값이다. 먼저 양쪽 VPN 연결을 확인하고 `iperf3 --version` 및 `command -v iperf3`로 도구 설치를 확인한다. 공인 UDP endpoint, 인증서 및 암호는 기록하지 않는다.

서버와 클라이언트 **각 터미널**에서 먼저 실행:

```sh
export SERVER_TUN_IP=10.8.1.1 IPERF_PORT=5201
```

클라이언트 터미널에서 추가로 실행:

```sh
export PING_COUNT=30 TEST_SECONDS=30 OMIT_SECONDS=2 PARALLEL_STREAMS=4
export UDP_RATE=250M UDP_PAYLOAD_BYTES=1200 SERVER_USER=paul
export UPLOAD_SOURCE=testdata/source-128MiB.bin UPLOAD_TARGET=/home/paul/autobricks_vpn/testdata/upload-received.bin
export DOWNLOAD_SOURCE=/home/paul/autobricks_vpn/testdata/source-128MiB.bin DOWNLOAD_TARGET=testdata/download-received.bin
```

`SERVER_TUN_IP`는 서버의 VPN 터널 주소, `IPERF_PORT`는 **터널 안에서만** 시험할 iperf3 수신 포트다. `SERVER_USER`는 서버 SSH 계정이다. 나머지 변수는 각각 ping 횟수, 전송·워밍업 시간, 병렬 연결 수, UDP 목표 전송률·데이터그램 크기, 시험 파일 경로다. 이 문서에 정한 값과 실제 환경이 다르면 명령 실행 전에 변경한 값을 시험 기록에 적고, 기존 결과와 같은 조건으로 비교하지 않는다. 각 케이스 시작 직전에 클라이언트에서 `RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')`를 실행해 회차 ID를 만든다. `status`는 명시된 판정에 따라 `PASS`/`FAIL`, 시험 자체를 완료하지 못하면 `INCONCLUSIVE`로 기록한다. 성능 수치의 단순 감소만으로 기능 실패라고 판정하지 않는다.

파일 케이스 준비는 최초 1회만 수행한다. M1 프로젝트 폴더에서 `mkdir -p testdata; test -e testdata/source-128MiB.bin || mkfile -n 128m testdata/source-128MiB.bin`, 서버 프로젝트 폴더에서 `mkdir -p testdata; test -e testdata/source-128MiB.bin || truncate -s 128M testdata/source-128MiB.bin`을 실행한다. 이후 원본 파일은 새로 만들거나 삭제하지 않고 재사용한다. 수신 파일은 같은 경로에 덮어쓰므로, 다른 용도의 파일이 없는지 최초 1회 확인한다. `testdata/`는 Git에서 제외한다. 서버의 iperf3 수신 포트는 계속 열어 두고, 기존 수신기가 있으면 재시작하지 않는다. 테스트용 TCP·UDP 포트에 클라이언트 터널 주소에서만 접근할 수 있어야 한다. 방화벽 변경은 서버 운영자의 승인된 절차로 진행한다.

TCP 30초는 이 그룹의 **고정 관측 시간**이지 링크의 이론적 최대 속도 보증이 아니다. 각 1초 구간과 정상 완료 요약을 모두 기록한다. 비교 대상도 동일한 30초·초기 2초 제외 조건으로 측정한다. UDP는 `250M`으로 먼저 실행하고, 한계 시험을 할 때만 `UDP_RATE=350M`으로 새 회차를 시작한다.

각 항목의 `서버 실행 명령`은 서버에서, `클라이언트 실행 명령`과 `명령`은 클라이언트에서 실행한다. `iperf3` 결과는 각 1초 구간과 마지막 `sender`·`receiver` 요약을 그대로 보관한다. `scp`는 실행 직전·직후 시각과 종료 코드를 기록하고, 양쪽 크기와 해시를 아래 명령으로 직접 읽는다. 사람이 확인할 수 없는 수치는 추정하지 않고 `미측정`으로 적는다.

| ID | 테스트 | 방법 |
|---|---|---|
| TC-01 | Ping | 클라이언트에서 서버 터널 주소로 ICMP를 반복 전송 |
| TC-02 | 파일 업로드 | 클라이언트에서 서버로 파일을 복사하고 원본과 대조 |
| TC-03 | 파일 다운로드 | 서버에서 클라이언트로 파일을 복사하고 원본과 대조 |
| TC-04 | TCP 단일 업로드 | 클라이언트에서 서버로 TCP 연결 하나를 연속 전송 |
| TC-05 | TCP 단일 다운로드 | 서버에서 클라이언트로 TCP 연결 하나를 연속 전송 |
| TC-06 | TCP 병렬 업로드 | 클라이언트 한 대에서 서버로 TCP 연결 여러 개를 동시 전송 |
| TC-07 | TCP 병렬 다운로드 | 서버에서 클라이언트 한 대로 TCP 연결 여러 개를 동시 전송 |
| TC-08 | UDP 업로드 | 클라이언트에서 서버로 지정 송신률의 UDP를 전송 |
| TC-09 | UDP 다운로드 | 서버에서 클라이언트로 지정 송신률의 UDP를 전송 |
| TC-10 | 연결 복구 | 네트워크 단절 또는 UDP endpoint 변경 후 연결을 재개 |
| TC-11 | 부하 중 연결 상태 | 전송 중과 종료 후 서버 터널 주소의 응답을 확인 |
| TC-12 | 서버 변경 회귀 | 서버 변경 전후 동일한 업로드·다운로드 케이스를 반복 |

### TC-01. Ping

- 목표: 단일 클라이언트와 서버 터널 주소 간 기본 연결 및 왕복 지연 확인.
- 서버 실행 명령: `ip -4 addr show dev autobricks0` 및 `systemctl is-active autobricks-vpn.service`.
- 클라이언트 실행 명령: 아래 `ping` 명령.
- 로그 양식: `run_id,TC-01,sent,received,loss_percent,rtt_min_ms,rtt_avg_ms,rtt_max_ms,rtt_stddev_ms,status`.
- 명령: `ping -c "$PING_COUNT" "$SERVER_TUN_IP"`
- 확인: 보낸 ICMP Echo의 순번과 각 응답 순번을 대조한다. 응답이 없는 순번은 실패로 기록한다.
- 계산: 손실률 = `(전송 수 - 수신 수) / 전송 수 × 100`. 응답한 패킷의 RTT로 최소·평균·최대·표준편차를 구한다.
- 판정: 수신 수가 전송 수보다 적으면 손실이다. RTT 증가 여부는 **동일 조건에서 측정한 이전 평균**과 수치로 비교한다. 서버가 아닌 클라이언트 자신의 터널 주소는 대상으로 사용하지 않는다.

### TC-02. 파일 업로드

- 목표: 클라이언트에서 서버로 파일을 완전하고 정확하게 전달.
- 서버 실행 명령: 전송 후 `sha256sum /home/paul/autobricks_vpn/testdata/upload-received.bin` 및 `stat -c %s /home/paul/autobricks_vpn/testdata/upload-received.bin`.
- 클라이언트 실행 명령: 아래 `scp` 명령과 전송 전 `stat -f %z "$UPLOAD_SOURCE"`.
- 로그 양식: `run_id,TC-02,source_bytes,target_bytes,source_digest,target_digest,elapsed_seconds,copy_exit_code,status`.
- 명령: `scp -o Compression=no "$UPLOAD_SOURCE" "$SERVER_USER@$SERVER_TUN_IP:$UPLOAD_TARGET"`. 복사 전 클라이언트에서 `shasum -a 256 "$UPLOAD_SOURCE"`, 복사 후 서버에서 `sha256sum "$UPLOAD_TARGET"`을 실행한다.
- 확인: 복사 명령의 종료 상태, 원본·대상 파일 크기와 SHA-256, 시작·종료 시각을 기록한다.
- 판정: 복사 오류, 크기 차이 또는 SHA-256 불일치가 있으면 실패다. 소요 시간은 같은 크기의 파일을 같은 조건에서 복사한 이전 결과와 비교한다.

### TC-03. 파일 다운로드

- 목표: 서버에서 클라이언트로 파일을 완전하고 정확하게 전달.
- 서버 실행 명령: 전송 전 `sha256sum /home/paul/autobricks_vpn/testdata/source-128MiB.bin` 및 `stat -c %s /home/paul/autobricks_vpn/testdata/source-128MiB.bin`.
- 클라이언트 실행 명령: 아래 `scp` 명령과 전송 후 `stat -f %z "$DOWNLOAD_TARGET"`.
- 로그 양식: `run_id,TC-03,source_bytes,target_bytes,source_digest,target_digest,elapsed_seconds,copy_exit_code,status`.
- 명령: `scp -o Compression=no "$SERVER_USER@$SERVER_TUN_IP:$DOWNLOAD_SOURCE" "$DOWNLOAD_TARGET"`. 복사 전 서버에서 `sha256sum "$DOWNLOAD_SOURCE"`, 복사 후 클라이언트에서 `shasum -a 256 "$DOWNLOAD_TARGET"`을 실행한다.
- 확인: 복사 명령의 종료 상태, 원본·대상 파일 크기와 SHA-256, 시작·종료 시각을 기록한다.
- 판정: 복사 오류, 크기 차이 또는 SHA-256 불일치가 있으면 실패다. 소요 시간은 같은 크기의 파일을 같은 조건에서 복사한 이전 결과와 비교한다.

### TC-04. TCP 단일 업로드

- 목표: 클라이언트→서버 단일 연결의 지속 처리량 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 아래 `iperf3` 명령.
- 로그 양식: `run_id,TC-04,interval_mbps,sender_mbps,receiver_mbps,retransmits,exit_code,completed,status`.
- 명령: `iperf3 -c "$SERVER_TUN_IP" -p "$IPERF_PORT" -t "$TEST_SECONDS" -O "$OMIT_SECONDS" -P 1 -i 1 -f m --connect-timeout 3000`
- 확인: 매 측정 구간의 BPS, 최종 송신·수신 BPS, 재전송 수, 정상 종료 여부를 기록한다.
- 판정: 연결 실패·비정상 종료·수신 결과 누락은 실패다. 진행 중 BPS가 0으로 떨어지면 그 시각과 지속 구간을 기록한다. 처리량·재전송 증감은 동일 조건의 이전 결과와 비교한다. 중단한 실행의 평균은 정상 처리량으로 사용하지 않는다.

### TC-05. TCP 단일 다운로드

- 목표: 서버→클라이언트 단일 연결의 지속 처리량 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 아래 `iperf3 -R` 명령.
- 로그 양식: `run_id,TC-05,interval_mbps,sender_mbps,receiver_mbps,retransmits,exit_code,completed,status`.
- 명령: `iperf3 -c "$SERVER_TUN_IP" -p "$IPERF_PORT" -R -t "$TEST_SECONDS" -O "$OMIT_SECONDS" -P 1 -i 1 -f m --connect-timeout 3000`
- 확인: 매 측정 구간의 BPS, 최종 송신·수신 BPS, 재전송 수, 정상 종료 여부를 기록한다.
- 판정: 연결 실패·비정상 종료·수신 결과 누락은 실패다. 진행 중 BPS가 0으로 떨어지면 그 시각과 지속 구간을 기록한다. 처리량·재전송 증감은 동일 조건의 이전 결과와 비교한다.

### TC-06. TCP 병렬 업로드

- 목표: 단일 클라이언트의 여러 동시 연결을 서버가 처리하는 능력 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 아래 `iperf3` 명령.
- 로그 양식: `run_id,TC-06,stream_count,per_stream_mbps,total_mbps,total_retransmits,completed_streams,status`.
- 명령: `iperf3 -c "$SERVER_TUN_IP" -p "$IPERF_PORT" -t "$TEST_SECONDS" -O "$OMIT_SECONDS" -P "$PARALLEL_STREAMS" -i 1 -f m --connect-timeout 3000`
- 확인: 연결별 BPS·재전송 수와 전체 합계, 정상 종료한 연결 수를 기록한다.
- 판정: 일부 연결이 끝나지 않거나 전체 합계가 0으로 멈추면 실패다. 연결 간 편차와 단일 업로드 대비 합계 변화는 수치로 비교한다.

### TC-07. TCP 병렬 다운로드

- 목표: 서버가 단일 클라이언트의 여러 동시 연결로 보내는 처리량 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 아래 `iperf3 -R` 명령.
- 로그 양식: `run_id,TC-07,stream_count,per_stream_mbps,total_mbps,total_retransmits,completed_streams,status`.
- 명령: `iperf3 -c "$SERVER_TUN_IP" -p "$IPERF_PORT" -R -t "$TEST_SECONDS" -O "$OMIT_SECONDS" -P "$PARALLEL_STREAMS" -i 1 -f m --connect-timeout 3000`
- 확인: 연결별 BPS·재전송 수와 전체 합계, 정상 종료한 연결 수를 기록한다.
- 판정: 일부 연결이 끝나지 않거나 전체 합계가 0으로 멈추면 실패다. 연결 간 편차와 단일 다운로드 대비 합계 변화는 수치로 비교한다.

### TC-08. UDP 업로드

- 목표: 지정 송신률에서 클라이언트→서버의 실제 UDP 수신 능력 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 아래 `iperf3 -u` 명령.
- 로그 양식: `run_id,TC-08,target_mbps,received_mbps,lost_datagrams,loss_percent,jitter_ms,completed,status`.
- 명령: `iperf3 -c "$SERVER_TUN_IP" -p "$IPERF_PORT" -u -b "$UDP_RATE" -l "$UDP_PAYLOAD_BYTES" -t "$TEST_SECONDS" -O "$OMIT_SECONDS" -P 1 -i 1 -f m --connect-timeout 3000`
- 확인: 지정 송신률, 실제 수신률, 송신·수신 datagram 수, 수신 측 손실률과 jitter를 기록한다.
- 계산: 손실률 = `(송신 datagram 수 - 수신 datagram 수) / 송신 datagram 수 × 100`. 도구가 손실 수를 제공하지 않으면 임의로 계산하지 않고 `미측정`으로 기록한다.
- 판정: 실제 수신률과 손실률·jitter를 동일 송신률의 이전 결과와 비교한다.

### TC-09. UDP 다운로드

- 목표: 지정 송신률에서 서버→클라이언트의 실제 UDP 수신 능력 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 아래 `iperf3 -u -R` 명령.
- 로그 양식: `run_id,TC-09,target_mbps,received_mbps,lost_datagrams,loss_percent,jitter_ms,completed,status`.
- 명령: `iperf3 -c "$SERVER_TUN_IP" -p "$IPERF_PORT" -u -R -b "$UDP_RATE" -l "$UDP_PAYLOAD_BYTES" -t "$TEST_SECONDS" -O "$OMIT_SECONDS" -P 1 -i 1 -f m --connect-timeout 3000`
- 확인: 지정 송신률, 실제 수신률, 송신·수신 datagram 수, 수신 측 손실률과 jitter를 기록한다.
- 계산: 손실률 = `(송신 datagram 수 - 수신 datagram 수) / 송신 datagram 수 × 100`. 도구가 손실 수를 제공하지 않으면 임의로 계산하지 않고 `미측정`으로 기록한다.
- 판정: 실제 수신률과 손실률·jitter를 동일 송신률의 이전 결과와 비교한다.

### TC-10. 연결 복구

- 목표: 단절 또는 UDP endpoint 변경 후 서버가 단일 클라이언트 연결을 다시 처리하는지 확인.
- 서버 실행 명령: 시험 직전 `START_TIME=$(date '+%Y-%m-%d %H:%M:%S')`를 실행한다. 시험 후 `systemctl show autobricks-vpn.service -p ActiveState -p MainPID -p NRestarts`와 `journalctl -u autobricks-vpn.service --since "$START_TIME" --no-pager`를 실행한다.
- 클라이언트 실행 명령: 복구 후 아래 `ping`과 TC-04의 `iperf3`를 실행한다. 네트워크 단절·전환은 승인된 별도 절차로 수행한다.
- 로그 양식: `run_id,TC-10,disconnect_time,restore_time,dtls_connected_time,first_reply_time,recovery_seconds,post_recovery_tcp_completed,status`.
- 방법: 단절·복구 또는 endpoint 변경 시각을 시계로 기록한 뒤, 복구 후 `ping -c "$PING_COUNT" "$SERVER_TUN_IP"`와 TC-04 명령을 실행한다. 네트워크 전환 자체는 별도의 승인된 시험 절차로 수행한다. 그 절차가 준비되지 않았으면 이 케이스는 실행하지 않고 `INCONCLUSIVE`로 기록한다.
- 확인: 단절·복구 시각, DTLS 재연결 완료 시각, endpoint 변경 전후의 서버 세션, 복구 후 서버 대상 ping 및 TCP 연결 성공 여부를 기록한다.
- 판정: 복구 후 DTLS 연결이 완료되지 않거나 ping·TCP가 다시 동작하지 않으면 실패다. 복구 시간은 복구 시각부터 첫 정상 패킷까지의 차이로 기록한다.

### TC-11. 부하 중 연결 상태

- 목표: 전송 부하가 걸린 동안과 종료 후 서버 터널의 응답 유지 확인.
- 서버 실행 명령: `iperf3 -s -B "$SERVER_TUN_IP" -p "$IPERF_PORT"` (이미 실행 중이면 재실행하지 않음).
- 클라이언트 실행 명령: 부하 전 `ping -c 5 "$SERVER_TUN_IP"`를 실행한다. 이어서 한 터미널에서 TC-04의 `iperf3`를 실행하고, 시작 직후 다른 터미널에서 `ping -c 5 "$SERVER_TUN_IP"`를 실행한다. `iperf3`가 끝난 뒤 다시 `ping -c 5 "$SERVER_TUN_IP"`를 실행한다.
- 로그 양식: `run_id,TC-11,phase,sent,received,loss_percent,rtt_avg_ms,tcp_completed,status` (`phase`는 `before`, `during`, `after`).
- 방법: 전·중·후 ping 5회씩의 요약(`packets transmitted/received`, packet loss, RTT avg)과 TC-04 완료 요약을 각 터미널에서 읽어 기록한다. 세 구간 중 하나라도 빠지면 `INCONCLUSIVE`로 기록한다.
- 확인: 부하 전·중·후에 같은 서버 터널 주소로 ping을 보내고 각 구간의 전송·수신 수와 평균 RTT를 기록한다.
- 판정: 부하 중 또는 종료 후 응답이 없으면 해당 구간의 손실로 기록한다. 평균 RTT 변화는 부하 전 수치와 비교한다. ping만으로 고장 위치를 단정하지 않는다.

### TC-12. 서버 변경 회귀

- 목표: 동일한 단일 클라이언트 조건에서 서버 변경의 영향을 확인.
- 서버 실행 명령: 변경 전후 `systemctl show autobricks-vpn.service -p ActiveState -p MainPID -p NRestarts` 및 TC-04의 `iperf3 -s`.
- 클라이언트 실행 명령: 변경 전후 동일한 값으로 TC-01·TC-04·TC-05의 명령을 반복한다.
- 로그 양식: `run_id,TC-12,phase,server_build,client_build,ping_loss_percent,ping_rtt_avg_ms,upload_mbps,download_mbps,upload_retransmits,download_retransmits,status`.
- 방법: 서버 변경 전후에 같은 변수 값으로 TC-01, TC-04, TC-05 명령을 각각 실행한다. 서버 서비스 변경 자체는 이 명령들에 포함하지 않는다.
- 확인: 클라이언트 빌드·경로·측정 조건을 고정하고 서버 변경 전후에 같은 TC-01·TC-04·TC-05 결과를 나란히 기록한다.
- 판정: 변경 후에만 전송이 정지하거나 손실이 생기면 회귀로 표시한다. 처리량과 재전송은 전후 수치를 그대로 비교하고, 조건이 달라졌다면 비교 불가로 기록한다.
