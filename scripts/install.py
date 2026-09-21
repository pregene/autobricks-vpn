#!/usr/bin/env python3
"""Interactive macOS/Linux server installer. Run through ./install.sh."""

import ctypes
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request


SOURCE = Path(__file__).resolve().parent.parent
PREFIX = Path("/opt/autobricks-vpn")
CONFIG_DIR = Path("/etc/autobricks-vpn")
CERT_DIR = CONFIG_DIR / "certs"
CONFIG = CONFIG_DIR / "server.ini"
PKI_PRIVATE = CONFIG_DIR / "root-private"
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")


def run(*args, cwd=None, env=None):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def ask(label, default):
    response = input(f"{label} [{default}]: ").strip()
    return response or default


def owner(path, user, group=None):
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid if group else pwd.getpwnam(user).pw_gid
    os.chown(path, uid, gid)


def write(path, content, mode=0o644):
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def need_tools(*names):
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise RuntimeError("필요한 명령이 없습니다: " + ", ".join(missing))


def verify_bin():
    bin_dir = SOURCE / "bin"
    suffix = "dylib" if MACOS else "so"
    required = [bin_dir / name for name in ("vpn-server", "vpn-client", f"libautobricks_vpn.{suffix}")]
    required.append(bin_dir / f"libwolfssl.{suffix}")
    if any(not path.is_file() for path in required):
        raise RuntimeError("bin/ 빌드 결과가 없습니다. 먼저 ./build.sh 또는 ./build.sh --release를 실행하세요")
    try:
        loaded = ctypes.CDLL(str(bin_dir / f"libautobricks_vpn.{suffix}"))
        loaded.autobricks_vpn_server_run
    except (OSError, AttributeError) as error:
        raise RuntimeError(f"bin/ VPN 라이브러리를 로드할 수 없습니다: {error}") from error
    return bin_dir


def install_program(source_bin):
    print("[1/3] bin/ 바이너리와 관리 웹 배치", flush=True)
    binary_dir = PREFIX / "bin"
    binary_dir.mkdir(parents=True, exist_ok=True)
    PREFIX.chmod(0o755)
    binary_dir.chmod(0o755)
    suffix = "dylib" if MACOS else "so"
    for name in ("vpn-server", "vpn-client", f"libautobricks_vpn.{suffix}"):
        temporary = binary_dir / (name + ".new")
        shutil.copy2(source_bin / name, temporary)
        temporary.replace(binary_dir / name)
    for library in source_bin.glob(f"libwolfssl*.{suffix}*"):
        if library.is_file():
            temporary = binary_dir / (library.name + ".new")
            shutil.copy2(library, temporary)
            temporary.replace(binary_dir / library.name)
    if LINUX:
        need_tools("ldconfig")
        write(Path("/etc/ld.so.conf.d/autobricks-vpn.conf"), str(binary_dir) + "\n")
        run("ldconfig")
    try:
        installed = ctypes.CDLL(str(binary_dir / f"libautobricks_vpn.{suffix}"))
        installed.autobricks_vpn_server_run
    except (OSError, AttributeError) as error:
        raise RuntimeError(f"VPN 공유 라이브러리를 로드할 수 없습니다: {error}") from error
    web = PREFIX / "web"
    web.mkdir(parents=True, exist_ok=True)
    web.chmod(0o755)
    for name in ("src", "public"):
        shutil.copytree(SOURCE / "web" / name, web / name, dirs_exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(SOURCE / "web" / name, web / name)
    run("npm", "ci", "--omit=dev", cwd=web)
    for directory, _, files in os.walk(web):
        Path(directory).chmod(0o755)
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    return binary_dir, web


def create_certificates(public_ip):
    print("[2/3] Root CA, Intermediate CA, 서버 인증서 생성", flush=True)
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    PKI_PRIVATE.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="autobricks-pki-") as temporary:
        p = Path(temporary)
        os.chmod(p, 0o700)
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096",
            "-out", "root-ca-key.pem", cwd=p)
        run("openssl", "req", "-new", "-x509", "-sha256", "-days", "3650",
            "-key", "root-ca-key.pem", "-out", "root-ca-cert.pem",
            "-subj", "/CN=Autobricks VPN Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=p)
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096",
            "-out", "intermediate-ca-key.pem", cwd=p)
        run("openssl", "req", "-new", "-sha256", "-key", "intermediate-ca-key.pem",
            "-out", "intermediate-ca.csr", "-subj", "/CN=Autobricks VPN Intermediate CA", cwd=p)
        write(p / "intermediate.ext", "basicConstraints=critical,CA:TRUE,pathlen:0\n"
              "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
              "authorityKeyIdentifier=keyid,issuer\n")
        run("openssl", "x509", "-req", "-sha256", "-days", "1825", "-in", "intermediate-ca.csr",
            "-CA", "root-ca-cert.pem", "-CAkey", "root-ca-key.pem", "-CAcreateserial",
            "-extfile", "intermediate.ext", "-out", "intermediate-ca-cert.pem", cwd=p)
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
            "-out", "server-key.pem", cwd=p)
        run("openssl", "req", "-new", "-sha256", "-key", "server-key.pem",
            "-out", "server.csr", "-subj", "/CN=Autobricks VPN Server", cwd=p)
        write(p / "server.ext", "basicConstraints=critical,CA:FALSE\n"
              "keyUsage=critical,digitalSignature,keyEncipherment\n"
              f"extendedKeyUsage=serverAuth\nsubjectAltName=IP:{public_ip}\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        run("openssl", "x509", "-req", "-sha256", "-days", "825", "-in", "server.csr",
            "-CA", "intermediate-ca-cert.pem", "-CAkey", "intermediate-ca-key.pem",
            "-CAcreateserial", "-extfile", "server.ext", "-out", "server-cert.pem", cwd=p)
        write(p / "trust-chain.pem", (p / "intermediate-ca-cert.pem").read_text() +
              (p / "root-ca-cert.pem").read_text(), 0o600)
        run("openssl", "verify", "-CAfile", "root-ca-cert.pem", "intermediate-ca-cert.pem", cwd=p)
        run("openssl", "verify", "-CAfile", "trust-chain.pem", "server-cert.pem", cwd=p)
        for name in ("root-ca-cert.pem", "intermediate-ca-cert.pem", "intermediate-ca-key.pem",
                     "server-cert.pem", "server-key.pem", "trust-chain.pem"):
            shutil.copy2(p / name, CERT_DIR / name)
            (CERT_DIR / name).chmod(0o600)
        shutil.copy2(p / "root-ca-key.pem", PKI_PRIVATE / "root-ca-key.pem")
        (PKI_PRIVATE / "root-ca-key.pem").chmod(0o600)


def create_config(public_ip, vpn_network, vpn_ip, port, web_group):
    content = f"""[server]
listen_address = 0.0.0.0
port = {port}
control_socket = /var/run/autobricks-vpn.sock
control_socket_group = {web_group}
certificate_file = {CERT_DIR}/server-cert.pem
private_key_file = {CERT_DIR}/server-key.pem
ca_file = {CERT_DIR}/trust-chain.pem
root_ca_file = {CERT_DIR}/root-ca-cert.pem
intermediate_ca_file = {CERT_DIR}/intermediate-ca-cert.pem
intermediate_ca_key_file = {CERT_DIR}/intermediate-ca-key.pem
public_address = {public_ip}
verify_client_san_ip = true
ocsp_enabled = false
tun_name = autobricks0
vpn_network = {vpn_network}
vpn_address = {vpn_ip}
dns_server = {vpn_ip}
mtu = 1350

[client]
"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    write(CONFIG, content, 0o600)


def permissions(web_user, web_group, web):
    owner(CONFIG_DIR, "root", web_group)
    CONFIG_DIR.chmod(0o750)
    owner(CONFIG, web_user)
    CERT_DIR.chmod(0o750)
    owner(CERT_DIR, "root", web_group)
    for name in ("root-ca-cert.pem", "intermediate-ca-cert.pem", "server-cert.pem", "trust-chain.pem"):
        (CERT_DIR / name).chmod(0o640)
        owner(CERT_DIR / name, "root", web_group)
    owner(CERT_DIR / "intermediate-ca-key.pem", "root", web_group)
    (CERT_DIR / "intermediate-ca-key.pem").chmod(0o640)
    owner(CERT_DIR / "server-key.pem", "root")
    (CERT_DIR / "server-key.pem").chmod(0o600)
    if PKI_PRIVATE.is_dir():
        owner(PKI_PRIVATE, "root")
        PKI_PRIVATE.chmod(0o700)
    data = web / "data"
    data.mkdir(exist_ok=True)
    saved_data = CONFIG_DIR / "web-data"
    if saved_data.is_dir() and not (data / "activity.json").exists():
        shutil.copytree(saved_data, data, dirs_exist_ok=True)
    owner(data, web_user)
    data.chmod(0o700)
    for directory, _, files in os.walk(data):
        owner(directory, web_user)
        for name in files:
            owner(Path(directory) / name, web_user)


def mac_services(binary_dir, web, web_user, node):
    helper = binary_dir / "run-with-failure-limit.sh"
    shutil.copy2(SOURCE / "scripts/run-with-failure-limit.sh", helper)
    helper.chmod(0o755)
    launch = Path("/Library/LaunchDaemons")
    jobs = [
        ("kr.co.autobricks.vpn-server", [helper, binary_dir / "vpn-server", "--config", CONFIG], None),
        ("kr.co.autobricks.vpn-web", [helper, node, web / "src/server.js"], web_user),
    ]
    from xml.sax.saxutils import escape
    for label, arguments, user in jobs:
        path = launch / f"{label}.plist"
        if path.exists():
            subprocess.run(["launchctl", "bootout", "system", str(path)], check=False)
        args = "".join(f"<string>{escape(str(arg))}</string>" for arg in arguments)
        user_entry = f"<key>UserName</key><string>{escape(user)}</string>" if user else ""
        web_entry = (f"<key>WorkingDirectory</key><string>{web}</string>"
                     f"<key>EnvironmentVariables</key><dict><key>VPN_CONFIG</key>"
                     f"<string>{CONFIG}</string></dict>") if user else ""
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
               '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
               f'<plist version="1.0"><dict><key>Label</key><string>{label}</string>'
               f'{user_entry}{web_entry}<key>ProgramArguments</key><array>{args}</array>'
               '<key>RunAtLoad</key><true/></dict></plist>\n')
        write(path, xml)
        run("plutil", "-lint", str(path))
        run("launchctl", "bootstrap", "system", str(path))


def linux_services(binary_dir, web, web_user, node):
    unit_dir = Path("/etc/systemd/system")
    unit_dir.mkdir(exist_ok=True)
    write(unit_dir / "autobricks-vpn.service", f"""[Unit]
Description=Autobricks VPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=infinity
StartLimitBurst=5

[Service]
Type=simple
ExecStart={binary_dir}/vpn-server --config {CONFIG}
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
    write(unit_dir / "autobricks-vpn-web.service", f"""[Unit]
Description=Autobricks VPN Web Console
After=network.target autobricks-vpn.service
Requires=autobricks-vpn.service
StartLimitIntervalSec=infinity
StartLimitBurst=5

[Service]
Type=simple
User={web_user}
Group={web_user}
WorkingDirectory={web}
Environment=NODE_ENV=production
Environment=VPN_CONFIG={CONFIG}
ExecStart={node} {web}/src/server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
    run("systemctl", "daemon-reload")
    for unit in ("autobricks-vpn.service", "autobricks-vpn-web.service"):
        run("systemctl", "enable", unit)
        run("systemctl", "reset-failed", unit)
        run("systemctl", "restart", unit)


def services_running():
    if MACOS:
        for label in ("kr.co.autobricks.vpn-server", "kr.co.autobricks.vpn-web"):
            result = subprocess.run(["launchctl", "print", "system/" + label],
                                    capture_output=True, text=True, check=False)
            if result.returncode or "state = running" not in result.stdout:
                return False
        return True
    return all(subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0
               for unit in ("autobricks-vpn.service", "autobricks-vpn-web.service"))


def main():
    if not (MACOS or LINUX):
        raise RuntimeError("서버 설치는 macOS와 Linux만 지원합니다")
    if os.geteuid() != 0:
        raise RuntimeError("sudo 권한이 필요합니다")
    os.umask(0o077)
    need_tools("python3", "openssl", "node", "npm")
    source_bin = verify_bin()
    if MACOS:
        web_user = os.environ.get("SUDO_USER")
        if not web_user or web_user == "root":
            raise RuntimeError("macOS에서는 일반 사용자 계정에서 ./install.sh를 실행하세요")
        web_group = "autobricks-vpn"
    else:
        web_user = web_group = "autobricks-vpn"
    existing = CONFIG.exists()
    if existing:
        required = [CERT_DIR / name for name in ("root-ca-cert.pem", "intermediate-ca-cert.pem",
                    "intermediate-ca-key.pem", "server-cert.pem", "server-key.pem", "trust-chain.pem")]
        if any(not path.is_file() for path in required):
            raise RuntimeError("기존 설정의 인증서가 일부 없습니다. 자동 재발급을 중단합니다")
        print("기존 server.ini와 인증서를 보존하고 프로그램과 서비스를 갱신합니다.")
    else:
        public_ip = str(ipaddress.IPv4Address(ask("서버 공개 IPv4 주소 (필수)", "")))
        vpn_network = ipaddress.IPv4Network(ask("VPN 대역", "10.9.1.0/24"), strict=True)
        vpn_ip = ipaddress.IPv4Address(ask("VPN 서버 주소", "10.9.1.1"))
        if vpn_ip not in vpn_network or vpn_ip in (vpn_network.network_address, vpn_network.broadcast_address):
            raise RuntimeError("VPN 서버 주소가 VPN 대역의 사용 가능한 호스트 주소가 아닙니다")
        port = int(ask("VPN UDP / 관리 웹 TCP 포트", "4433"))
        if not 1 <= port <= 65535:
            raise RuntimeError("포트는 1~65535여야 합니다")
    if MACOS:
        try:
            grp.getgrnam(web_group)
        except KeyError:
            run("dseditgroup", "-o", "create", web_group)
        run("dseditgroup", "-o", "edit", "-a", web_user, "-t", "user", web_group)
    elif web_user not in [entry.pw_name for entry in pwd.getpwall()]:
        run("useradd", "--system", "--user-group", "--no-create-home", web_user)
    binary_dir, web = install_program(source_bin)
    if not existing:
        create_certificates(public_ip)
        create_config(public_ip, str(vpn_network), str(vpn_ip), port, web_group)
    permissions(web_user, web_group, web)
    node = shutil.which("node")
    print("[3/3] VPN 및 관리 웹 서비스 등록·시작", flush=True)
    if MACOS:
        mac_services(binary_dir, web, web_user, node)
    else:
        linux_services(binary_dir, web, web_user, node)
    web_port = next((line.split("=", 1)[1].strip() for line in CONFIG.read_text().splitlines()
                     if line.startswith("port =")), "4433")
    url = f"http://127.0.0.1:{web_port}/api/status"
    for _ in range(20):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                status = json.load(response)
            if status.get("vpn", {}).get("state") == "online" and services_running():
                break
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError("서비스를 등록했지만 VPN/웹 상태가 online이 아닙니다. 서비스 로그를 확인하세요")
    print(f"설치 완료. 관리 웹: http://127.0.0.1:{web_port}")
    if (PKI_PRIVATE / "root-ca-key.pem").is_file():
        print(f"Root CA 개인키: {PKI_PRIVATE}/root-ca-key.pem (오프라인 백업 필요)")
    saved_data = CONFIG_DIR / "web-data"
    if saved_data.is_dir():
        shutil.rmtree(saved_data)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"설치 실패: {error}", file=sys.stderr)
        sys.exit(1)
