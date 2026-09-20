# VPN 서버·클라이언트 인증서 발급 및 검증 규정

서버 인증서와 클라이언트 인증서는 Root CA가 서명한 Intermediate CA에서 각각 발급한다. 모든 인증서는 확장 필드를 포함한 **X.509 v3**로 발급하고 운용한다. 서버와 클라이언트 인증서의 SAN과 `extendedKeyUsage`는 용도에 따라 다르게 작성한다. 아래 IP 주소는 문서용 예시다. 실제 주체 값, 키 알고리즘, 유효기간은 발급 전에 확정한다.

## X.509 v3와 유효기간

발급 명령의 `-days` 값은 인증서 종류별로 따로 정한다. 값은 양의 정수이며 발급일로부터의 일수다. 이 문서에서는 기간을 임의로 고정하지 않는다.

| 인증서 | 발급 변수 | 만료 조건 |
| --- | --- | --- |
| Root CA | `ROOT_DAYS` | 전체 체인에서 가장 늦게 만료 |
| Intermediate CA | `INTERMEDIATE_DAYS` | Root CA보다 먼저 만료 |
| 서버 | `SERVER_DAYS` | Intermediate CA보다 먼저 만료 |
| 클라이언트 | `CLIENT_DAYS` | Intermediate CA보다 먼저 만료 |

`-days` 숫자만 비교하지 말고 발급 후 각 인증서의 실제 `notBefore`·`notAfter`를 확인한다. 상위 CA의 유효기간 밖으로 벗어나는 하위 인증서는 발급하지 않는다. 이 문서의 `basicConstraints`, `keyUsage`, `extendedKeyUsage`, SAN은 X.509 v3 확장이다. 각 인증서에 대해 `CERT_FILE`을 지정하고 버전·확장·유효기간을 확인한다.

```sh
openssl x509 -in "$CERT_FILE" -noout -text
openssl x509 -in "$CERT_FILE" -noout -dates
```

## 주체 정보와 SAN

서버와 클라이언트의 주체(DN)는 각각 발급 전에 값을 정한다. 다음 항목을 기록하며, 값을 임의로 채우지 않는다. DN 값은 인증서의 주체 정보이며 VPN 주소 검증에는 사용하지 않는다.

| 항목 | 의미 |
| --- | --- |
| `C` | 국가 코드 |
| `ST`, `L` | 지역·도시 |
| `O`, `OU` | 조직·조직 단위 |
| `CN` | 서버 또는 클라이언트 이름 |
| `UID` | 사용자 식별자 (`userId`) |
| `DC` | 도메인 구성요소 (`domainComponent`); 여러 개 입력 가능 |
| `serialNumber` | 주체의 장치·자산 번호 등; 인증서 자체의 일련번호와 별개 |
| `GN`, `SN`, `initials` | 이름·성·이니셜 |
| `title`, `description`, `pseudonym` | 직책·설명·별칭 |
| `street`, `postalCode`, `businessCategory`, `organizationIdentifier` | 주소·조직 식별 정보 |
| `dnQualifier`, `generationQualifier` | DN 또는 이름의 추가 구분자 |
| `emailAddress` | 연락처 메일 주소 |

CSR의 `-subj`에는 확정된 값을 넣는다. 예를 들면 `SERVER_SUBJECT`와 `CLIENT_SUBJECT`를 각각 `/C=.../ST=.../L=.../O=.../OU=.../CN=.../UID=.../serialNumber=.../emailAddress=...` 형식으로 지정한다. 필요하지 않은 DN 항목은 생략한다. `DC`는 `/DC=.../DC=...`처럼 반복할 수 있다. OpenSSL에서 대문자 `UID`는 `userId`이며 소문자 `uid`는 별도 속성 `uniqueIdentifier`이므로 혼동하지 않는다. `DNS`·`email` SAN은 아래 확장 설정에 넣으며, DN의 `CN`·`emailAddress`와 별개 항목이다.

`DID`는 OpenSSL의 기본 DN 속성 이름이 아니다. **장치 ID**를 뜻한다면 발급 정책에 따라 `serialNumber` 또는 `UID`에 넣을 수 있다. **분산 식별자(Decentralized Identifier)**를 뜻한다면 별도의 등록된 OID를 사용하는 사용자 정의 DN 속성이나 URI SAN 형식을 정해야 한다. 어느 경우든 VPN 라이브러리가 그 값을 접속 허용에 사용하려면 명시적인 검증 규칙이 필요하다.

## Subject Alternative Name (SAN)

SAN은 DN과 별도로 서버 접속 주소, 클라이언트 VPN 주소, 선택적 이름과 정책을 기록한다. 같은 종류의 값이 여러 개 필요하면 OpenSSL 설정에서 `IP.1`, `IP.2` 또는 `DNS.1`, `DNS.2`처럼 번호를 붙인다.

| SAN 종류 | 서버 인증서 | 클라이언트 인증서 | VPN 처리 규칙 |
| --- | --- | --- | --- |
| `IP` (`iPAddress`) | 클라이언트가 접속하는 서버 IP | 할당받을 VPN 내부 IP | 각각 접속 주소와 등록된 VPN IP에 정확히 일치해야 함 |
| `DNS` (`dNSName`) | DNS 이름으로 접속하는 경우의 서버 이름 | 필요한 경우 클라이언트 이름 | - |
| `email` (`rfc822Name`) | 선택적 메일 주소 | 선택적 메일 주소 | - |
| `URI` (`uniformResourceIdentifier`) | 별도 규정 없음 | 선택적 출발지 CIDR 정책 | 아래 `urn:autobricks:allowed-source-cidr:` 규칙 적용 |
| `otherName`, `dirName`, `RID` | 별도 규정 없음 | 별도 규정 없음 | - |

`IP` SAN의 값은 개별 주소다. IP 범위를 `IP:192.0.2.*`처럼 쓰지 않으며, 클라이언트 출발지 CIDR은 아래 URI SAN 형식으로 기록한다. `DNS` SAN은 DN의 `CN`·`DC`와 다르고, `email` SAN은 DN의 `emailAddress`와 다르다.

## Root CA 인증서 생성

Root CA는 자체 서명한다. `ROOT_SUBJECT`에 확정된 `C`, `O`, `CN` 등의 값을 지정한다. 아래 RSA 3072비트와 AES-256 암호화는 생성 예시이며, `ROOT_DAYS`는 확정된 유효기간이다. 개인키 생성 시 암호를 대화형으로 입력한다.

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -aes-256-cbc -out root-ca-key.pem
openssl req -new -x509 -key root-ca-key.pem -subj "$ROOT_SUBJECT" \
  -days "$ROOT_DAYS" -sha256 \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out root-ca-cert.pem
openssl verify -CAfile root-ca-cert.pem root-ca-cert.pem
```

Root CA의 `pathlen:1`은 아래에 Intermediate CA 한 단계를 허용한다. Root CA 개인키는 서버·클라이언트 VPN 프로세스에 제공하지 않는다.

## Intermediate CA 인증서 생성

Intermediate CA는 별도 개인키와 CSR을 만들고 Root CA로 서명한다. `INTERMEDIATE_SUBJECT`와 `INTERMEDIATE_DAYS`에 확정된 DN과 유효기간을 지정한다. 개인키는 암호화하며 서명할 때 암호를 대화형으로 입력한다.

```ini
# intermediate.ext
[intermediate_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
```

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -aes-256-cbc -out intermediate-ca-key.pem
openssl req -new -key intermediate-ca-key.pem \
  -subj "$INTERMEDIATE_SUBJECT" -out intermediate-ca.csr
openssl x509 -req -in intermediate-ca.csr \
  -CA root-ca-cert.pem -CAkey root-ca-key.pem -CAcreateserial \
  -days "$INTERMEDIATE_DAYS" -sha256 \
  -extfile intermediate.ext -extensions intermediate_ca \
  -out intermediate-ca-cert.pem
openssl verify -CAfile root-ca-cert.pem intermediate-ca-cert.pem
```

`pathlen:0`은 이 CA가 다른 하위 CA를 발급하지 않고 서버·클라이언트 leaf 인증서만 발급하도록 제한한다.

## 서버 인증서 생성

서버 인증서의 IP SAN에는 **클라이언트가 접속할 서버 주소**를 넣는다. 서버의 VPN 터널 주소를 대신 넣지 않는다. EKU는 `serverAuth`다.

```ini
# server.ext — 192.0.2.10을 실제 서버 접속 주소로 교체
[server_cert]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @server_names

[server_names]
IP.1 = 192.0.2.10
# DNS.1 = <서버 DNS 이름: 필요한 경우>
# email.1 = <서버 메일 주소: 필요한 경우>
```

서버 개인키와 CSR을 만들고 Intermediate CA로 서명한다. 아래 RSA 3072비트는 키 생성 예시이며, `$SERVER_SUBJECT`와 `$SERVER_DAYS`는 승인된 DN과 유효기간을 입력한 뒤 사용한다.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server-key.pem
openssl req -new -key server-key.pem -subj "$SERVER_SUBJECT" -out server.csr
openssl x509 -req -in server.csr \
  -CA intermediate-ca-cert.pem -CAkey intermediate-ca-key.pem -CAcreateserial \
  -days "$SERVER_DAYS" -sha256 -extfile server.ext -extensions server_cert \
  -out server-cert.pem
openssl verify -purpose sslserver -verify_ip 192.0.2.10 \
  -CAfile root-ca-cert.pem -untrusted intermediate-ca-cert.pem server-cert.pem
```

VPN 클라이언트는 CA 체인을 검증하고, 서버 인증서의 IP SAN이 자신이 접속한 서버 주소와 일치하는지 검사한다.

## 클라이언트 인증서 생성

클라이언트 인증서의 **IP SAN**에는 그 클라이언트에 고정된 VPN 내부 IP를 넣는다. EKU는 `clientAuth`다.

접속 출발지 범위를 인증서에 넣을 때는 다음 **애플리케이션 전용 URI SAN**을 사용한다.

```text
urn:autobricks:allowed-source-cidr:<IPv4 네트워크>/<접두사 길이>
```

아래 `10.0.0.2`는 예시 VPN IP, `192.0.2.0/24`는 예시 출발지 범위다. 출발지 제한을 두지 않을 클라이언트는 `URI.1` 줄을 생략한다.

```ini
# client.ext
[client_cert]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @client_names

[client_names]
IP.1 = 10.0.0.2
URI.1 = urn:autobricks:allowed-source-cidr:192.0.2.0/24
# DNS.1 = <클라이언트 DNS 이름: 필요한 경우>
# email.1 = <클라이언트 메일 주소: 필요한 경우>
```

클라이언트마다 별도 개인키와 CSR을 만들고 Intermediate CA로 서명한다. 아래 RSA 3072비트는 키 생성 예시이며, `$CLIENT_SUBJECT`와 `$CLIENT_DAYS`는 해당 클라이언트에 승인된 값으로 지정한다.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out client-key.pem
openssl req -new -key client-key.pem -subj "$CLIENT_SUBJECT" -out client.csr
openssl x509 -req -in client.csr \
  -CA intermediate-ca-cert.pem -CAkey intermediate-ca-key.pem -CAcreateserial \
  -days "$CLIENT_DAYS" -sha256 -extfile client.ext -extensions client_cert \
  -out client-cert.pem
openssl verify -purpose sslclient \
  -CAfile root-ca-cert.pem -untrusted intermediate-ca-cert.pem client-cert.pem
```

## 서버의 클라이언트 검증

서버 설정은 클라이언트 인증서의 SHA-256 지문을 VPN IP에 연결한다. 인증서의 IP SAN과 서버 설정의 VPN IP가 정확히 같아야 한다.

서버의 검증 규칙은 다음과 같다.

1. CA 체인과 클라이언트 인증서를 검증한다.
2. 인증서 지문으로 서버에 등록된 VPN IP를 찾고, 그 IP가 클라이언트 인증서의 IP SAN에 있는지 확인한다.
3. 위 접두사의 URI SAN이 **없으면** 출발지 IP에 대한 추가 제한을 두지 않는다. 다른 인증 검사는 그대로 수행한다.
4. URI SAN이 **하나 있으면** 서버가 UDP 소켓에서 관측한 클라이언트 IPv4 주소가 지정된 CIDR에 속할 때만 연결을 승인한다. 출발지 포트는 비교하지 않는다.
5. 해당 URI가 둘 이상이거나, CIDR이 잘못됐거나, 네트워크 주소에 host bit가 설정돼 있으면 연결을 거부한다. `urn:autobricks:`로 시작하지만 알 수 없는 정책 URI도 거부한다. 해석 오류를 무제한 허용으로 바꾸지 않는다.

클라이언트가 NAT 뒤에 있으면 검증 대상은 클라이언트 장치의 사설 IP가 아니라 **서버가 관측한 NAT 이후 출발지 IP**다. 인증서의 일반 IP SAN에 여러 주소를 넣어도 주소 범위가 되지는 않는다. 이 URI의 의미는 X.509의 기본 검증 규칙이 아니라 이 VPN 서버가 구현해야 하는 규칙이다.

형식 근거: [RFC 5280의 SAN 정의](https://www.rfc-editor.org/rfc/rfc5280), [RFC 4514의 DN 이름](https://www.rfc-editor.org/rfc/rfc4514), [OpenSSL의 X.509 확장 설정](https://docs.openssl.org/3.4/man5/x509v3_config/), [개인키 생성](https://docs.openssl.org/3.4/man1/openssl-genpkey/), [CSR·자체 서명](https://docs.openssl.org/3.4/man1/openssl-req/), [CA 서명](https://docs.openssl.org/3.4/man1/openssl-x509/).
