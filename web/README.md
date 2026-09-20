# Autobricks VPN Web

Express 기반의 로컬 VPN 운영 화면입니다. `server.ini`에 등록된 클라이언트, 실시간 연결 상태와 최근 100건의 접속·해지 및 서버 시작·종료 이벤트를 보여줍니다. 추가 팝업은 Intermediate CA로 클라이언트 인증서를 발급하고 단일 `client.ini`를 다운로드합니다. 삭제 팝업은 등록을 제거하고 VPN 서버의 연결을 끊습니다.

## 실행

```sh
cd web
npm ci
npm start
```

주소는 `server.ini`의 `[server] port`를 읽어 `127.0.0.1`에만 TCP로 엽니다. VPN 서버는 같은 번호의 UDP 포트를 사용하므로 서로 충돌하지 않습니다.

```sh
VPN_CONFIG=/etc/autobricks-vpn/server.ini npm start
```

`WEB_HOST`나 별도 웹 포트는 사용하지 않습니다. 관리 화면은 항상 loopback 전용입니다. VPN 제어 소켓은 웹 프로세스가 접근할 수 있는 그룹 권한이 필요합니다.

## API

- `GET /api/health`: 웹 프로세스 health와 uptime
- `GET /api/status`: 웹 상태와 VPN 연동 상태
- `GET /api/clients`: `server.ini`의 `[client]` 등록 목록
- `POST /api/clients/issue`: Intermediate CA로 클라이언트 인증서 발급, 지문 등록, `[client]`·`[certificate]`·`[key]`·`[ca]`가 포함된 단일 `client.ini` 다운로드
- `PUT /api/clients/:vpnAddress`: 인증서 SHA-256 지문을 VPN IP에 등록 또는 교체
- `DELETE /api/clients/:vpnAddress`: 클라이언트 등록 해제 후 VPN 서버 설정 즉시 갱신 및 활성 연결 종료
- `GET /api/vpn/events`: Rust 서버의 연결 상태를 받는 SSE 스트림
- `GET /api/activity`: 서버 시작·종료와 클라이언트 접속·해지의 최근 100건
- `GET /api/activity/events`: 최근 이벤트 목록의 SSE 스트림
- `DELETE /api/vpn/sessions/:vpnAddress`: 해당 VPN IP의 활성 세션 종료

기존 `/api/pki`와 CSR 요청 API는 호환용으로 남아 있지만, 추가 팝업의 발급 흐름에는 사용하지 않습니다.

추가 팝업의 로그인 ID와 암호는 선택 사항이며 함께 입력해야 합니다. 둘 다 비워 두면 인증서만 확인합니다. 입력하면 서버 `server.ini`의 해당 `[client]` 항목에 `VPN_IP = 지문 ID 암호` 형식으로 저장되고, VPN 클라이언트가 실행 중 터미널에서 ID와 암호를 입력받습니다. 로그인 전에는 VPN 패킷을 전달하지 않습니다. 다운로드하는 클라이언트 INI에는 ID와 암호가 포함되지 않습니다.

발급을 사용하려면 `server.ini`의 `[server]`에 `certificate_file`, `root_ca_file`, `intermediate_ca_file`, `intermediate_ca_key_file`, `public_address`를 설정합니다. `public_address`는 서버 인증서의 IP SAN과 일치해야 합니다. 다운로드한 INI에는 개인키가 포함되므로 배포할 때 파일 권한을 소유자 전용으로 설정하세요 (`chmod 600 client.ini`).

서버 인증서를 한 파일로 관리하려면 `server.ini`에 `[certificate]`(서버 인증서), `[key]`(서버 개인키), `[ca]`(클라이언트 인증서 검증용 CA 체인)를 추가합니다. 발급용 CA도 `[root_ca]`, `[intermediate_ca]`, `[intermediate_key]`에 넣을 수 있습니다. 내장 섹션이 있으면 파일 경로보다 우선합니다. 개인키가 들어 있는 `server.ini`는 `chmod 600`으로 보호하세요.

## 실시간 연결 상태

Express는 `server.ini`의 `control_socket`에 `WATCH` 구독을 연결하고 Rust VPN 서버가 push하는 세션 변경 이벤트를 브라우저 SSE로 전달합니다. 브라우저와 Express 어느 쪽도 연결 상태 확인을 위한 주기적 polling을 수행하지 않습니다. 클라이언트 삭제는 등록과 활성 세션을 함께 제거합니다. 클라이언트가 별도 종료 메시지 없이 멈춘 경우 서버는 마지막 활동 후 300초에 세션을 제거합니다.

기본 control socket은 `/var/run/autobricks-vpn.sock`이며 VPN 서버가 `0660` 권한으로 생성합니다. `server.ini`에 `control_socket_group = staff`처럼 웹 프로세스가 속한 그룹을 지정한 뒤 VPN 서버를 다시 시작하면 해당 그룹이 소켓에 적용됩니다. macOS에서 일반 사용자로 웹을 실행할 때 사용할 수 있습니다.

운영 이벤트는 웹 프로세스가 VPN 제어 소켓에서 관찰한 변화를 기록합니다. 최근 100건은 Git에서 제외된 `web/data/activity.json`에 저장되어 웹 재시작 후에도 유지됩니다. 웹이 꺼져 있던 동안의 클라이언트 접속·해지는 소급해서 기록되지 않습니다.

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

클라이언트 발급에는 웹 프로세스가 Intermediate CA 개인키를 읽습니다. 따라서 웹은 로컬 주소에만 노출하고 `server.ini` 및 개인키 접근 권한을 제한해야 합니다. 웹의 레거시 PKI 등록·CSR 요청 데이터는 메모리에만 유지되며, 해당 API는 실제 클라이언트 발급 경로와 별개입니다.
