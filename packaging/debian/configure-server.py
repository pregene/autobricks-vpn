#!/usr/bin/env python3
"""Create the initial Autobricks VPN server PKI and configuration."""

import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


CONFIG_DIR = Path("/etc/autobricks-vpn")
CERT_DIR = CONFIG_DIR / "certs"
PRIVATE_DIR = CONFIG_DIR / "root-private"
CONFIG = CONFIG_DIR / "server.ini"
SUBJECT_PATTERN = re.compile(r"^[A-Za-z0-9 .,_@()+-]{1,128}$")


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def subject_value(label, value):
    value = value.strip()
    if not SUBJECT_PATTERN.fullmatch(value):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def subject(args, common_name):
    values = (
        ("C", args.country),
        ("ST", args.state),
        ("L", args.locality),
        ("O", args.organization),
        ("OU", args.organizational_unit),
        ("CN", common_name),
    )
    return "".join(f"/{key}={subject_value(key, value)}" for key, value in values)


def write(path, content, mode=0o600):
    path.write_text(content, encoding="ascii")
    path.chmod(mode)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--vpn-network", required=True)
    parser.add_argument("--vpn-address", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--country", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--locality", required=True)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--organizational-unit", required=True)
    parser.add_argument("--root-ca-cn", required=True)
    parser.add_argument("--intermediate-ca-cn", required=True)
    parser.add_argument("--server-cn", required=True)
    return parser.parse_args()


def validate(args):
    if not re.fullmatch(r"[A-Za-z]{2}", args.country):
        raise ValueError("country must contain exactly two ASCII letters")
    args.country = args.country.upper()
    public_ip = ipaddress.IPv4Address(args.public_ip)
    network = ipaddress.IPv4Network(args.vpn_network, strict=True)
    vpn_address = ipaddress.IPv4Address(args.vpn_address)
    if vpn_address not in network or vpn_address in (network.network_address, network.broadcast_address):
        raise ValueError("VPN server address is not a usable address in the VPN network")
    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    for label, value in (
        ("state", args.state),
        ("locality", args.locality),
        ("organization", args.organization),
        ("organizational unit", args.organizational_unit),
        ("Root CA common name", args.root_ca_cn),
        ("Intermediate CA common name", args.intermediate_ca_cn),
        ("server common name", args.server_cn),
    ):
        subject_value(label, value)
    return public_ip, network, vpn_address


def create_pki(args, public_ip, destination):
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", "root-ca-key.pem", cwd=destination)
    run("openssl", "req", "-new", "-x509", "-sha256", "-days", "3650", "-key", "root-ca-key.pem", "-out", "root-ca-cert.pem", "-subj", subject(args, args.root_ca_cn), "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=destination)
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", "intermediate-ca-key.pem", cwd=destination)
    run("openssl", "req", "-new", "-sha256", "-key", "intermediate-ca-key.pem", "-out", "intermediate-ca.csr", "-subj", subject(args, args.intermediate_ca_cn), cwd=destination)
    write(destination / "intermediate.ext", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run("openssl", "x509", "-req", "-sha256", "-days", "1825", "-in", "intermediate-ca.csr", "-CA", "root-ca-cert.pem", "-CAkey", "root-ca-key.pem", "-CAcreateserial", "-extfile", "intermediate.ext", "-out", "intermediate-ca-cert.pem", cwd=destination)
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", "server-key.pem", cwd=destination)
    run("openssl", "req", "-new", "-sha256", "-key", "server-key.pem", "-out", "server.csr", "-subj", subject(args, args.server_cn), cwd=destination)
    write(destination / "server.ext", f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:{public_ip}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run("openssl", "x509", "-req", "-sha256", "-days", "825", "-in", "server.csr", "-CA", "intermediate-ca-cert.pem", "-CAkey", "intermediate-ca-key.pem", "-CAcreateserial", "-extfile", "server.ext", "-out", "server-cert.pem", cwd=destination)
    (destination / "trust-chain.pem").write_text((destination / "intermediate-ca-cert.pem").read_text() + (destination / "root-ca-cert.pem").read_text(), encoding="ascii")
    run("openssl", "verify", "-CAfile", "root-ca-cert.pem", "intermediate-ca-cert.pem", cwd=destination)
    run("openssl", "verify", "-CAfile", "trust-chain.pem", "server-cert.pem", cwd=destination)
    certificate_text = subprocess.check_output(["openssl", "x509", "-in", str(destination / "server-cert.pem"), "-noout", "-ext", "subjectAltName"], text=True)
    if f"IP Address:{public_ip}" not in certificate_text:
        raise RuntimeError("server certificate IP SAN verification failed")


def install_pki(source):
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR.chmod(0o700)
    for name in ("root-ca-cert.pem", "intermediate-ca-cert.pem", "intermediate-ca-key.pem", "server-cert.pem", "server-key.pem", "trust-chain.pem"):
        shutil.copy2(source / name, CERT_DIR / name)
        (CERT_DIR / name).chmod(0o600)
    shutil.copy2(source / "root-ca-key.pem", PRIVATE_DIR / "root-ca-key.pem")
    (PRIVATE_DIR / "root-ca-key.pem").chmod(0o600)


def create_config(args, public_ip, network, vpn_address):
    content = f"""[server]
listen_address = 0.0.0.0
port = {args.port}
control_socket = /var/run/autobricks-vpn.sock
control_socket_group = autobricks
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
vpn_network = {network}
vpn_address = {vpn_address}
dns_server = {vpn_address}
mtu = 1350

[client]
"""
    temporary = CONFIG.with_name("server.ini.new")
    write(temporary, content)
    temporary.replace(CONFIG)


def main():
    args = parse_arguments()
    public_ip, network, vpn_address = validate(args)
    if CONFIG.exists():
        required = tuple(CERT_DIR / name for name in ("root-ca-cert.pem", "intermediate-ca-cert.pem", "intermediate-ca-key.pem", "server-cert.pem", "server-key.pem", "trust-chain.pem"))
        if not all(path.is_file() for path in required):
            raise RuntimeError("existing certificate set is incomplete; certificates were not regenerated")
        print("Existing configuration and certificates were preserved.")
        return
    if CONFIG_DIR.exists() and any(CONFIG_DIR.iterdir()):
        raise RuntimeError("configuration directory is not empty; refusing to overwrite it")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="autobricks-pki-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        create_pki(args, public_ip, directory)
        install_pki(directory)
    create_config(args, public_ip, network, vpn_address)
    print("Initial server PKI and configuration were created.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Configuration failed: {error}")
