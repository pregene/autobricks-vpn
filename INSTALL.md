# Autobricks VPN 서버 설치

## Ubuntu 22.04 DEB 설치

GitHub Release에서 서버 아키텍처에 맞는 `amd64` 또는 `arm64` DEB와 동일한
이름의 `.sha256` 파일을 내려받습니다.

```sh
sha256sum -c autobricks-vpn-server-0.8.107-ubunbtu-22.04-ARCH.deb.sha256
sudo dpkg -i autobricks-vpn-server-0.8.107-ubunbtu-22.04-ARCH.deb
```

최초 설치는 공개 IPv4, VPN 대역·서버 주소·포트, 인증서 국가·지역·조직 및
Root CA·Intermediate CA·서버 CN을 영어로 입력받습니다. Root CA,
Intermediate CA, 서버 인증서와 `/etc/autobricks-vpn/server.ini`를 생성하고
`autobricks-vpn.service`, `autobricks-vpn-web.service`를 등록합니다. Root CA
개인키 `/etc/autobricks-vpn/root-private/root-ca-key.pem`은 반드시 별도
보관합니다.

VPN 서비스에는 Node.js가 필요하지 않습니다. 관리 웹은 Node.js 18 이상이
필요하며 Ubuntu 22.04에서는 Node.js 22 LTS를 권장합니다.

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
sudo systemctl reset-failed autobricks-vpn-web.service
sudo systemctl restart autobricks-vpn-web.service
```

DEB 빌드와 설치·삭제 동작의 상세 내용은
[`packaging/debian/README.md`](packaging/debian/README.md)를 참고합니다.

## 소스 빌드 설치

macOS와 Linux 서버는 저장소 최상위에서 **빌드한 뒤 설치**합니다. Windows 서버는 지원하지 않습니다.

```sh
./build.sh
./install.sh
```

배포용 최적화 빌드를 원하면 첫 명령 대신 `./build.sh --release`를 실행합니다. 기본 `./build.sh`는 debug 빌드입니다. 두 경우 모두 `bin/`에 `vpn-server`, `vpn-client`, VPN 공유 라이브러리와 wolfSSL 공유 라이브러리를 배치합니다. `bin/`과 `dependens/`는 Git에서 제외됩니다. 빌드 스크립트가 wolfSSL 소스를 준비하고 DTLS 1.3으로 빌드·검증한 뒤 Cargo 빌드를 실행합니다. `install.sh`는 **빌드를 하지 않으며**, 완성된 `bin/`이 없거나 라이브러리 로딩에 실패하면 시작 전에 중단합니다.

제거는 `./uninstall.sh`입니다. 서비스와 `/opt/autobricks-vpn` 실행 파일을 제거하되 `/etc/autobricks-vpn`의 설정·인증서와 웹 이벤트 데이터는 보존합니다. 같은 설정으로 재설치할 때 기존 CA와 클라이언트 등록을 다시 사용합니다.

제거 후에도 저장소의 `bin/`·`dependens/` 빌드 결과와 설치 과정에서 만든 운영체제 계정·그룹은 유지됩니다. 다시 설치하려면 필요에 따라 `./build.sh`를 실행한 뒤 `./install.sh`를 실행합니다.

```sh
./uninstall.sh
```

설정, 모든 CA·서버 개인키, 클라이언트 등록과 이벤트 데이터까지 영구 삭제하려면 `--purge`를 명시합니다. 백업을 확인한 뒤 실행하세요.

```sh
./uninstall.sh --purge
```

설치 프로그램이 관리자 권한을 요청하고, 최초 설치에서는 **필수 공개 IPv4 주소**, VPN 대역·서버 IP, 포트를 입력받습니다. 공개 주소는 클라이언트가 접속할 주소이며 서버 인증서의 SAN IP가 됩니다. 다른 항목은 Enter를 누르면 표시된 기본값을 사용합니다. 설치는 `bin/` 결과물을 시스템 경로에 복사하고 Root CA → Intermediate CA → 서버 인증서를 생성한 뒤 관리 웹과 시스템 서비스를 시작합니다. 설치한 VPN 공유 라이브러리도 서비스 등록 전에 로딩을 검사합니다. 웹은 `http://127.0.0.1:<입력한 포트>`에서 열립니다. macOS는 실행한 일반 사용자 계정으로 웹을 실행하고 전용 `autobricks-vpn` 그룹을 만들며, Linux는 `autobricks-vpn` 시스템 계정을 만듭니다. 빌드에는 Rust/C 빌드 도구, Git, Make, Autoconf·Automake·Libtool, pkg-config가 필요하며 Linux에는 `patchelf`도 필요합니다. 설치와 클라이언트 인증서 발급에는 OpenSSL, Node.js와 npm이 필요합니다. wolfSSL 소스가 없으면 **빌드 단계**에서 다운로드합니다.

이미 터미널에서 VPN 서버 또는 웹을 수동 실행 중이라면 설치 전에 해당 프로세스를 종료하세요. 같은 UDP/TCP 포트를 새 서비스가 사용할 수 있어야 합니다.

기존 `/etc/autobricks-vpn/server.ini`가 있으면 인증서와 클라이언트 등록을 **보존**하고 새 `bin/`의 프로그램 및 서비스를 갱신합니다. 기존 인증서 파일이 일부 없으면 자동으로 새 CA를 만들지 않고 중단합니다. 설치 후 `/etc/autobricks-vpn/root-private/root-ca-key.pem`은 별도 장소에 백업하세요. VPN 서버와 웹의 정상 실행, 실제 클라이언트 연결은 설치 후 확인해야 합니다.

아래는 설치 프로그램이 수행하는 작업과 수동 복구를 위한 상세 절차입니다. 일반 설치에서는 직접 실행할 필요가 없습니다.

## 수동 설치 참고

빌드 명령은 저장소 최상위 디렉터리에서 시작합니다. 인증서 작업은 반드시 저장소 밖에서 진행합니다.

## 설치 전에 결정할 값

- `PUBLIC_IP`: 클라이언트가 실제로 접속할 서버의 IPv4 주소. 서버 인증서의 SAN IP와 반드시 같아야 합니다. NAT를 사용하면 내부 LAN 주소가 아니라 클라이언트 INI에 넣을 주소를 선택합니다.
- `VPN_NETWORK`, `VPN_IP`: 예를 들어 `10.9.1.0/24`, `10.9.1.1`. 기존 LAN 대역과 겹치지 않게 정합니다.
- `PORT`: 기본값 `4433`. VPN은 UDP, 관리 웹은 같은 번호의 loopback TCP를 사용합니다.
- 관리 웹 실행 계정: `server.ini`를 읽고 수정하며 Intermediate CA 키를 읽을 수 있어야 합니다. 관리 웹은 `127.0.0.1`에만 바인딩됩니다.

서버에는 Rust/C 빌드 도구, DTLS 1.3을 활성화해 빌드한 wolfSSL, Node.js와 npm, OpenSSL CLI가 필요합니다. wolfSSL 빌드 옵션은 [README.md](README.md#개발환경-구성)를 참고합니다. 설치 후 클라이언트 인증서를 발급할 때도 관리 웹에서 OpenSSL CLI를 호출합니다.

## 1. 바이너리와 웹 준비

`build.sh`는 아래와 같은 순서로 wolfSSL을 먼저 준비합니다. DTLS 1.3과 필요한 X.509 옵션이 포함된 빌드만 VPN 빌드에 사용합니다.

```sh
mkdir -p dependens
git clone --depth 1 --branch v5.8.2-stable \
  https://github.com/wolfSSL/wolfssl.git dependens/wolfssl
cd dependens/wolfssl && sh autogen.sh && cd ../..
mkdir -p dependens/wolfssl-build
cd dependens/wolfssl-build
../wolfssl/configure --prefix="$(pwd)/../wolfssl-install" \
  --enable-dtls --enable-dtls13 --enable-dtls-mtu \
  --enable-crl --enable-ocsp --enable-opensslextra --enable-ip-alt-name
make -j4 && make install
cd ../..
```

기존 wolfSSL 빌드가 있는 경우 `build.sh`가 DTLS 1.3 설정과 공유 라이브러리 로딩을 확인한 뒤 재사용합니다. 검증에 실패하면 `bin/` 배치를 중단합니다.

```sh
WOLFSSL_PREFIX="$PWD/dependens/wolfssl-install" cargo build --release --features dtls13
```

서버용 설치 디렉터리에 `vpn-server`, `libautobricks_vpn` 공유 라이브러리, wolfSSL 공유 라이브러리와 웹 디렉터리를 배치합니다. `vpn-server`는 **자신과 같은 디렉터리**에서 `libautobricks_vpn.dylib`(macOS) 또는 `libautobricks_vpn.so`(Linux)를 찾습니다. wolfSSL은 운영체제 동적 로더가 찾을 수 있어야 합니다. macOS에서 `bin/`에 wolfSSL dylib을 함께 둘 경우 `otool -L`로 참조 경로를 확인하고 `@loader_path` 기반으로 조정해야 합니다. Linux는 설치된 라이브러리 경로를 `ldconfig`에 등록하거나 바이너리에 rpath를 설정합니다. 실행 전 다음으로 로딩을 확인합니다.

```sh
# macOS
otool -L /opt/autobricks-vpn/bin/libautobricks_vpn.dylib
# Linux
ldd /opt/autobricks-vpn/bin/libautobricks_vpn.so
```

이하 예시는 프로그램이 `/opt/autobricks-vpn`, 설정이 `/etc/autobricks-vpn/server.ini`, 인증서가 `/etc/autobricks-vpn/certs`에 있다고 가정합니다. 실제 설치 경로가 다르면 모두 일치시켜야 합니다.

## 2. 최초 인증서 생성

기존 설치에는 이 단계를 다시 실행하지 마세요. CA를 새로 만들면 기존 클라이언트가 서버와 서로를 신뢰하지 못합니다. 인증서는 Root CA → Intermediate CA → 서버 순서로 만듭니다. Root CA 개인키는 발급 완료 후 별도 안전한 장소에 백업하고 운영 웹에 제공하지 않습니다.

```sh
umask 077
mkdir -m 700 ~/autobricks-vpn-pki-new
cd ~/autobricks-vpn-pki-new

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out root-ca-key.pem
openssl req -new -x509 -sha256 -days 3650 \
  -key root-ca-key.pem -out root-ca-cert.pem \
  -subj '/CN=Autobricks VPN Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out intermediate-ca-key.pem
openssl req -new -sha256 -key intermediate-ca-key.pem \
  -out intermediate-ca.csr -subj '/CN=Autobricks VPN Intermediate CA'
cat > intermediate.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -sha256 -days 1825 -in intermediate-ca.csr \
  -CA root-ca-cert.pem -CAkey root-ca-key.pem -CAcreateserial \
  -extfile intermediate.ext -out intermediate-ca-cert.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server-key.pem
openssl req -new -sha256 -key server-key.pem \
  -out server.csr -subj '/CN=Autobricks VPN Server'
```

다음 파일의 `PUBLIC_IP`를 실제 주소로 바꾼 뒤 서버 인증서를 서명합니다.

```sh
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:PUBLIC_IP
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -sha256 -days 825 -in server.csr \
  -CA intermediate-ca-cert.pem -CAkey intermediate-ca-key.pem -CAcreateserial \
  -extfile server.ext -out server-cert.pem
cat intermediate-ca-cert.pem root-ca-cert.pem > trust-chain.pem

openssl verify -CAfile root-ca-cert.pem intermediate-ca-cert.pem
openssl verify -CAfile trust-chain.pem server-cert.pem
openssl x509 -in server-cert.pem -noout -ext subjectAltName
```

마지막 명령에 설정한 IP가 표시되는지 확인합니다. `root-ca-key.pem`은 서버의 런타임에 필요하지 않습니다. 백업 완료 전에는 삭제하지 마세요. 서버의 `trust-chain.pem`은 클라이언트 인증서를 검증하는 데 쓰고, 웹은 Root/Intermediate 인증서와 Intermediate 개인키로 새 클라이언트를 발급합니다.

## 3. 서버 설정과 권한

인증서 파일을 `/etc/autobricks-vpn/certs/`에 복사합니다. `root-ca-key.pem`, CSR, serial 파일은 복사하지 않습니다. 아래 명령은 앞 단계의 `~/autobricks-vpn-pki-new` 안에서 실행합니다.

```sh
sudo install -d -m 0700 /etc/autobricks-vpn/certs
sudo install -m 0600 root-ca-cert.pem intermediate-ca-cert.pem \
  intermediate-ca-key.pem server-cert.pem server-key.pem trust-chain.pem \
  /etc/autobricks-vpn/certs/
```

`/etc/autobricks-vpn/server.ini`에는 다음 값을 넣습니다. 인증서를 파일 경로로 지정하면 내장 PEM 섹션 없이도 동작합니다.

```ini
[server]
listen_address = 0.0.0.0
port = 4433
control_socket = /var/run/autobricks-vpn.sock
control_socket_group = autobricks-vpn
certificate_file = /etc/autobricks-vpn/certs/server-cert.pem
private_key_file = /etc/autobricks-vpn/certs/server-key.pem
ca_file = /etc/autobricks-vpn/certs/trust-chain.pem
root_ca_file = /etc/autobricks-vpn/certs/root-ca-cert.pem
intermediate_ca_file = /etc/autobricks-vpn/certs/intermediate-ca-cert.pem
intermediate_ca_key_file = /etc/autobricks-vpn/certs/intermediate-ca-key.pem
public_address = PUBLIC_IP
verify_client_san_ip = true
ocsp_enabled = false
tun_name = autobricks0
vpn_network = 10.9.1.0/24
vpn_address = 10.9.1.1
dns_server = 10.9.1.1
mtu = 1350

[client]
```

`PUBLIC_IP`, VPN 주소·대역, 소켓 그룹을 설치 환경에 맞게 변경합니다. macOS에서도 공용 `staff` 그룹 대신 웹 계정만 속한 전용 그룹을 사용합니다. OCSP 서비스를 따로 구성하지 않았다면 예시처럼 끕니다. 서버는 TUN 및 라우팅 설정에 관리자 권한이 필요합니다. 웹 실행 계정은 `server.ini`를 **읽고 수정**할 수 있어야 하고 Intermediate 개인키도 읽을 수 있어야 합니다. 서버는 root로 실행하면 이 파일을 읽을 수 있습니다. 설정 파일과 개인키에 일반 사용자 접근 권한을 주지 마세요. 예를 들어 웹 전용 계정 `autobricks-vpn`을 쓴다면 설정과 Intermediate 키를 그 계정 소유의 `0600`으로 두고, 개인키를 보관한 디렉터리에는 해당 계정만 들어갈 수 있게 합니다. 웹 이벤트 기록을 위해 `/opt/autobricks-vpn/web/data`도 웹 계정이 쓸 수 있어야 합니다.

웹이 수정하는 `[client]` 등록 정보와 선택적 로그인 암호는 `server.ini`에 저장됩니다. 따라서 설정 파일을 백업할 때도 개인키와 동일하게 취급해야 합니다. 관리 웹은 로컬 TCP에서만 접근할 수 있으므로 원격 관리가 필요하면 별도의 인증된 접근 경로를 마련합니다.

## 4. 서비스 등록

### macOS: launchd

macOS에는 서버용 시스템 LaunchDaemon과 웹용 LaunchDaemon을 각각 등록합니다. 서버는 root, 웹은 `server.ini`와 Intermediate 키에 접근 가능한 전용 계정으로 실행합니다. macOS `KeepAlive`만으로는 실패 5회 제한을 설정할 수 없으므로 두 작업 모두 `scripts/run-with-failure-limit.sh`를 통해 실행합니다. 이 스크립트는 실패하면 즉시 다시 실행하고, 최초 실행을 포함해 5회 연속 실패하면 종료합니다. 종료 후에는 관리자가 원인을 수정하고 서비스를 다시 시작해야 합니다. plist의 경로와 계정 이름을 실제 값으로 바꿉니다.

```sh
sudo install -m 0755 scripts/run-with-failure-limit.sh /opt/autobricks-vpn/bin/
```

다음은 **서버 plist 예시**입니다.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>kr.co.autobricks.vpn-server</string>
  <key>ProgramArguments</key><array>
    <string>/opt/autobricks-vpn/bin/run-with-failure-limit.sh</string>
    <string>/opt/autobricks-vpn/bin/vpn-server</string>
    <string>--config</string><string>/etc/autobricks-vpn/server.ini</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/var/log/autobricks-vpn-server.log</string>
  <key>StandardErrorPath</key><string>/var/log/autobricks-vpn-server.log</string>
</dict></plist>
```

**웹 plist 예시**입니다. `WEB_USER`를 실제 macOS 계정으로 바꾸고 Node 실행 경로를 `command -v node`로 확인합니다. 웹의 `data/` 쓰기 권한과 제어 소켓 그룹 권한도 맞춰야 합니다.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>kr.co.autobricks.vpn-web</string>
  <key>UserName</key><string>WEB_USER</string>
  <key>WorkingDirectory</key><string>/opt/autobricks-vpn/web</string>
  <key>EnvironmentVariables</key><dict>
    <key>VPN_CONFIG</key><string>/etc/autobricks-vpn/server.ini</string>
    <key>NODE_ENV</key><string>production</string>
  </dict>
  <key>ProgramArguments</key><array>
    <string>/opt/autobricks-vpn/bin/run-with-failure-limit.sh</string>
    <string>/usr/local/bin/node</string><string>/opt/autobricks-vpn/web/src/server.js</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
```

각 plist를 `/Library/LaunchDaemons/kr.co.autobricks.vpn-server.plist`, `/Library/LaunchDaemons/kr.co.autobricks.vpn-web.plist`에 `root:wheel`, `0644`로 설치합니다. 서버를 먼저 시작해 제어 소켓이 생성된 뒤 웹을 시작합니다.

```sh
sudo plutil -lint /Library/LaunchDaemons/kr.co.autobricks.vpn-*.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/kr.co.autobricks.vpn-server.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/kr.co.autobricks.vpn-web.plist
sudo launchctl print system/kr.co.autobricks.vpn-server
sudo launchctl print system/kr.co.autobricks.vpn-web
```

실패 원인을 고친 뒤 수동으로 다시 시작할 때는 `sudo launchctl kickstart -k system/kr.co.autobricks.vpn-server` 또는 웹 작업의 label을 사용합니다.

### Linux: systemd

`/etc/systemd/system/autobricks-vpn.service`의 예시입니다. 서버는 root로 TUN을 만들고, 웹은 기존 [웹 unit](web/deploy/autobricks-vpn-web.service)을 전용 계정으로 실행합니다. 웹 unit의 Node 경로와 그룹이 실제 환경에 맞는지 확인합니다.

```ini
[Unit]
Description=Autobricks VPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=infinity
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/opt/autobricks-vpn/bin/vpn-server --config /etc/autobricks-vpn/server.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

웹 unit은 `web/deploy/autobricks-vpn-web.service`를 `/etc/systemd/system/`에 설치할 수 있습니다. 해당 unit은 서버가 시작된 뒤 웹을 시작하며, 웹은 전용 계정으로 동작합니다. 두 unit 모두 첫 실행을 포함해 최대 5회 시작하며 `RestartSec`를 지정하지 않아 systemd의 기본 재시작 지연값을 따릅니다. 설정한 재시작 제한과 복구 방법은 [웹 운영 문서](web/README.md#systemd-재시작-제한)에 있습니다.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now autobricks-vpn.service
sudo systemctl enable --now autobricks-vpn-web.service
systemctl status autobricks-vpn.service autobricks-vpn-web.service
```

## 5. 설치 확인과 업그레이드

```sh
curl --fail http://127.0.0.1:4433/api/health
curl --fail http://127.0.0.1:4433/api/status
```

웹 브라우저에서 `http://127.0.0.1:4433`을 열어 서버 상태를 확인합니다. 클라이언트 한 명을 추가해 단일 `client.ini`를 내려받고, 다른 기기에서 DTLS 접속과 VPN IP 통신을 시험합니다. UDP `4433`에 대한 방화벽/NAT 설정은 별도로 필요할 수 있습니다. 서버와 웹 로그에서 인증서·권한·동적 라이브러리 로딩 오류가 없는지 확인합니다.

업그레이드 시에는 **기존 `/etc/autobricks-vpn/server.ini`, CA 및 서버 개인키, 웹 이벤트 데이터**를 보존합니다. 바이너리와 웹 코드만 교체하고 서비스를 재시작합니다. CA 또는 서버 공개 주소를 바꿀 때는 별도의 인증서 재발급 및 클라이언트 재배포 계획을 먼저 세워야 합니다.
