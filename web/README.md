# Autobricks VPN Web

Express 기반의 VPN 서버 운영 웹 프로젝트입니다. 서버 인증서 등록과 클라이언트 인증서 발급 요청을 다루는 PKI 운영 화면/API를 제공하며, Rust VPN 프로세스에 대한 제어 권한은 아직 연결하지 않습니다.

## 실행

```sh
cd web
npm install
npm run dev
```

주소는 `server.ini`의 `[server] port`를 읽어 `127.0.0.1`에만 TCP로 엽니다. 현재 설정에서는 `http://127.0.0.1:4433`입니다. VPN 서버는 같은 번호의 UDP 포트를 사용하므로 서로 충돌하지 않습니다.

```sh
VPN_CONFIG=/etc/autobricks-vpn/server.ini npm start
```

`WEB_HOST`나 별도 웹 포트는 사용하지 않습니다. 관리 화면은 항상 loopback 전용입니다.

## API

- `GET /api/health`: 웹 프로세스 health와 uptime
- `GET /api/status`: 웹 상태와 VPN 연동 상태
- `GET /api/pki`: 인증서, 발급 요청, 서명 서비스 capability
- `POST /api/pki/server-certificates`: 서버 인증서 PEM 검사 및 개인키 경로 참조 등록
- `POST /api/pki/client-certificates`: 클라이언트 CSR, VPN IP, 유효기간 발급 요청 접수
- `GET /api/clients`: `server.ini`의 `[client]` 등록 목록
- `PUT /api/clients/:vpnAddress`: 인증서 SHA-256 지문을 VPN IP에 등록 또는 교체
- `DELETE /api/clients/:vpnAddress`: 클라이언트 등록 해제
- `GET /api/vpn/events`: Rust 서버의 연결 상태를 받는 SSE 실시간 스트림
- `DELETE /api/vpn/sessions/:vpnAddress`: 해당 VPN IP의 활성 DTLS 세션 종료

## 실시간 연결 상태

Express는 `server.ini`의 `control_socket`에 지속적인 `WATCH` 구독을 연결하고 Rust VPN 서버가 push하는 세션 변경 이벤트를 브라우저 SSE로 전달합니다. 브라우저와 Express 어느 쪽도 연결 상태 확인을 위한 주기적 polling을 수행하지 않습니다. 웹의 **연결 끊기**는 활성 세션만 종료하며 클라이언트 등록을 폐기하지 않습니다.

기본 control socket은 `/var/run/autobricks-vpn.sock`이며 VPN 서버가 `0660` 권한으로 생성합니다. 웹 프로세스가 접근할 수 있도록 두 서비스를 같은 운영 그룹으로 구성해야 합니다.

## systemd 재시작 제한

`deploy/autobricks-vpn-web.service`는 프로세스가 오류로 종료되면 3초 후 다시 시작하지만 최대 5회까지만 시작합니다. `StartLimitIntervalSec=infinity`를 사용하므로 시간이 지난다고 실패 횟수가 자동 초기화되지 않습니다. 다섯 번째 실행도 실패하면 systemd가 재시작을 중단하고 unit을 `failed` 상태로 유지합니다. 원인을 수정한 다음 관리자가 명시적으로 다음 명령을 실행해야 다시 시작합니다.

```sh
sudo systemctl reset-failed autobricks-vpn-web.service
sudo systemctl start autobricks-vpn-web.service
```

기존 `autobricks-vpn.service`에는 unit 파일을 덮어쓰지 않고 `deploy/autobricks-vpn.service.d/restart-limit.conf` 파일 하나만 drop-in으로 설치합니다.

```text
/etc/systemd/system/autobricks-vpn.service.d/restart-limit.conf
```

```sh
sudo install -D -m 0644 \
  deploy/autobricks-vpn.service.d/restart-limit.conf \
  /etc/systemd/system/autobricks-vpn.service.d/restart-limit.conf
```

설치 후에는 `sudo systemctl daemon-reload`가 필요합니다. 서버의 기존 service 사용자, 그룹, 실행 경로를 확인하기 전에는 예제 unit을 그대로 설치하지 않습니다.

VPN 서버도 오류 종료 후 3초 간격으로 재시작하며 최대 5회 실패하면 `failed` 상태로 멈춥니다. 복구할 때는 다음처럼 실패 횟수를 명시적으로 초기화합니다.

```sh
sudo systemctl reset-failed autobricks-vpn.service
sudo systemctl start autobricks-vpn.service
```

현재 PKI 데이터는 프로세스 메모리에만 유지되며 재시작하면 사라집니다. 서버 인증서 등록 시에도 개인키 내용은 받지 않고 서버측 절대 경로 참조만 받습니다. 클라이언트 발급은 CSR 접수까지 동작하며 실제 서명과 폐기는 `not_configured` 상태입니다.

운영 단계에서는 다음 경계를 유지합니다.

- 웹 프로세스는 CA 개인키와 서버 개인키를 읽지 않습니다.
- 별도 권한으로 실행되는 CA 서명 서비스가 CSR 서명과 CRL/OCSP 폐기를 담당합니다.
- 제한된 Unix domain socket을 통해 서명 결과와 SHA-256 지문/VPN IP 매핑만 VPN 서버에 전달합니다.
- 외부 공개 전 관리자 인증, CSRF 방어, TLS, 감사 로그, 영구 데이터 저장소를 추가합니다.
