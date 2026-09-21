#!/usr/bin/env python3
"""Build Ubuntu 22.04 amd64 and arm64 server DEB packages with Docker."""

import os
import hashlib
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()
ARCHITECTURES = {"amd64": "linux/amd64", "arm64": "linux/arm64"}


def run(*args, cwd=None):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def copy_tree(source, destination):
    shutil.copytree(source, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns("node_modules"))


def executable(path):
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build_linux(architecture, platform, output):
    image = f"autobricks-vpn-deb-builder:22.04-{architecture}"
    run("docker", "build", "--platform", platform, "-t", image,
        "-f", str(ROOT / "packaging/debian/Dockerfile.build"), str(ROOT))
    source_mount = f"{ROOT}:/source:ro"
    output_mount = f"{output}:/output"
    command = r"""
set -eux
mkdir /work
tar -C /source --exclude=./.git --exclude=./target --exclude=./build --exclude=./bin --exclude=./certs --exclude=./config --exclude=./dependens --exclude=./web/node_modules -cf - . | tar -C /work -xf -
cd /work
WOLFSSL_PREFIX=/wolfssl-install cargo build --release --features dtls13
cp target/release/vpn-server target/release/libautobricks_vpn.so /output/
cp -a /wolfssl-install/lib/libwolfssl.so* /output/
patchelf --set-rpath '$ORIGIN' /output/libautobricks_vpn.so
/output/vpn-server --help
ldd /output/libautobricks_vpn.so
"""
    run("docker", "run", "--rm", "--platform", platform, "-v", source_mount, "-v", output_mount, image, "bash", "-lc", command)


def stage_package(architecture, artifacts, root):
    debian = root / "DEBIAN"
    binary = root / "opt/autobricks-vpn/bin"
    scripts = root / "opt/autobricks-vpn/scripts"
    web = root / "opt/autobricks-vpn/web"
    units = root / "lib/systemd/system"
    for directory in (debian, binary, scripts, web, units):
        directory.mkdir(parents=True, exist_ok=True)

    for name in ("vpn-server", "libautobricks_vpn.so"):
        shutil.copy2(artifacts / name, binary / name)
    for library in artifacts.glob("libwolfssl.so*"):
        if library.is_symlink():
            os.symlink(os.readlink(library), binary / library.name)
        else:
            shutil.copy2(library, binary / library.name)
    copy_tree(ROOT / "web", web)
    if not (ROOT / "web/node_modules").is_dir():
        raise RuntimeError("web/node_modules is missing; run npm ci --omit=dev in web first")
    shutil.copytree(ROOT / "web/node_modules", web / "node_modules", symlinks=True)
    shutil.copy2(ROOT / "packaging/debian/configure-server.py", scripts / "configure-server.py")
    shutil.copy2(ROOT / "packaging/debian/autobricks-vpn.service", units / "autobricks-vpn.service")
    shutil.copy2(ROOT / "packaging/debian/autobricks-vpn-web.service", units / "autobricks-vpn-web.service")

    installed_size = sum(path.stat().st_size for path in root.rglob("*") if path.is_file()) // 1024
    control = f"""Package: autobricks-vpn-server
Version: {VERSION}
Section: net
Priority: optional
Architecture: {architecture}
Essential: no
Installed-Size: {installed_size}
Maintainer: Autobricks <support@autobricks.co.kr>
Depends: libc6 (>= 2.35), python3, openssl, iproute2, debconf, adduser, systemd
Recommends: nodejs (>= 18)
Description: Autobricks DTLS VPN server and local management web
 Provides the VPN server, certificate setup, client certificate management,
 and systemd services for Ubuntu 22.04 and later.
"""
    (debian / "control").write_text(control, encoding="ascii")
    for name in ("templates", "config", "postinst", "prerm", "postrm"):
        shutil.copy2(ROOT / "packaging/debian" / name, debian / name)
    for name in ("config", "postinst", "prerm", "postrm"):
        executable(debian / name)
    executable(scripts / "configure-server.py")


def build_deb(architecture, package_root, destination):
    run("docker", "run", "--rm", "--platform", ARCHITECTURES[architecture], "-v", f"{package_root}:/package", "-v", f"{BUILD}:/output", "ubuntu:22.04", "bash", "-lc", f"dpkg-deb --build --root-owner-group /package /output/{destination.name}")


def write_checksum(package):
    digest = hashlib.sha256()
    with package.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    checksum = package.with_name(f"{package.name}.sha256")
    checksum.write_text(f"{digest.hexdigest()}  {package.name}\n", encoding="ascii")


def main():
    if shutil.which("docker") is None:
        raise RuntimeError("docker is required")
    BUILD.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="autobricks-deb-", dir=BUILD) as temporary:
        temporary = Path(temporary)
        for architecture, platform in ARCHITECTURES.items():
            artifacts = temporary / f"artifacts-{architecture}"
            package_root = temporary / f"package-{architecture}"
            artifacts.mkdir()
            build_linux(architecture, platform, artifacts)
            stage_package(architecture, artifacts, package_root)
            destination = BUILD / f"autobricks-vpn-server-{VERSION}-ubunbtu-22.04-{architecture}.deb"
            build_deb(architecture, package_root, destination)
            write_checksum(destination)
    print("Packages created:")
    for architecture in ARCHITECTURES:
        package = BUILD / f"autobricks-vpn-server-{VERSION}-ubunbtu-22.04-{architecture}.deb"
        print(package)
        print(package.with_name(f"{package.name}.sha256"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"DEB build failed: {error}")
