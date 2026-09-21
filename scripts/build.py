#!/usr/bin/env python3
"""Build local wolfSSL and VPN launchers into the ignored bin/ directory."""

import argparse
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import sys


SOURCE = Path(__file__).resolve().parent.parent
DEPENDENCIES = SOURCE / "dependens"
BIN = SOURCE / "bin"
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")


def run(*args, cwd=None, env=None):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def need_tools(*names):
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise RuntimeError("필요한 명령이 없습니다: " + ", ".join(missing))


def wolfssl():
    print("[1/3] wolfSSL DTLS 1.3 준비", flush=True)
    source = DEPENDENCIES / "wolfssl"
    install = DEPENDENCIES / "wolfssl-install"
    suffix = "dylib" if MACOS else "so"
    library = install / "lib" / f"libwolfssl.{suffix}"
    ready = (install / "include/wolfssl/options.h").is_file() and library.is_file()
    if not ready:
        need_tools("git", "make", "autoreconf")
        DEPENDENCIES.mkdir(exist_ok=True)
        if not source.is_dir():
            run("git", "clone", "--depth", "1", "--branch", "v5.8.2-stable",
                "https://github.com/wolfSSL/wolfssl.git", str(source))
        run("sh", "autogen.sh", cwd=source)
        build = DEPENDENCIES / "wolfssl-build"
        build.mkdir(exist_ok=True)
        configure = [str(source / "configure"), f"--prefix={install}",
                     "--enable-dtls", "--enable-dtls13", "--enable-dtls-mtu",
                     "--enable-crl", "--enable-ocsp", "--enable-opensslextra",
                     "--enable-ip-alt-name"]
        if os.uname().machine in ("x86_64", "amd64"):
            configure.append("--enable-aesni")
        run(*configure, cwd=build)
        run("make", "-j4", cwd=build)
        run("make", "install", cwd=build)
    options = (install / "include/wolfssl/options.h").read_text()
    if "#define WOLFSSL_DTLS13" not in options:
        raise RuntimeError("설치된 wolfSSL에 DTLS 1.3이 없습니다")
    try:
        shared = ctypes.CDLL(str(library))
        if shared.wolfSSL_Init() != 1:
            raise RuntimeError("wolfSSL_Init이 실패했습니다")
        shared.wolfSSL_Cleanup()
    except OSError as error:
        raise RuntimeError(f"wolfSSL을 로드할 수 없습니다: {error}") from error
    return install


def copy_artifact(source, destination):
    temporary = destination.with_name(destination.name + ".new")
    shutil.copy2(source, temporary)
    temporary.replace(destination)


def build_vpn(prefix, release):
    print("[2/3] VPN 빌드" + (" (release)" if release else " (debug)"), flush=True)
    need_tools("cargo")
    args = ["cargo", "build", "--features", "dtls13"]
    if release:
        args.append("--release")
    run(*args, cwd=SOURCE, env={**os.environ, "WOLFSSL_PREFIX": str(prefix)})
    return SOURCE / "target" / ("release" if release else "debug")


def stage(target, prefix):
    print("[3/3] bin/ 배치와 동적 라이브러리 검사", flush=True)
    BIN.mkdir(exist_ok=True)
    suffix = "dylib" if MACOS else "so"
    for name in ("vpn-server", "vpn-client", f"libautobricks_vpn.{suffix}"):
        copy_artifact(target / name, BIN / name)
    libraries = list((prefix / "lib").glob(f"libwolfssl*.{suffix}*"))
    if not libraries:
        raise RuntimeError("wolfSSL 공유 라이브러리 파일이 없습니다")
    for library in libraries:
        if library.is_file():
            copy_artifact(library, BIN / library.name)
    vpn_library = BIN / f"libautobricks_vpn.{suffix}"
    if MACOS:
        need_tools("otool", "install_name_tool", "codesign")
        references = subprocess.check_output(["otool", "-L", str(vpn_library)], text=True)
        for line in references.splitlines()[1:]:
            reference = line.strip().split(" ")[0]
            if "libwolfssl" in reference:
                run("install_name_tool", "-change", reference,
                    "@loader_path/" + Path(reference).name, str(vpn_library))
        run("codesign", "--force", "--sign", "-", str(vpn_library))
    else:
        need_tools("patchelf")
        run("patchelf", "--set-rpath", "$ORIGIN", str(vpn_library))
    try:
        loaded = ctypes.CDLL(str(vpn_library))
        loaded.autobricks_vpn_server_run
    except (OSError, AttributeError) as error:
        raise RuntimeError(f"bin/ VPN 라이브러리를 로드할 수 없습니다: {error}") from error
    print("빌드 완료:", BIN)


def main():
    parser = argparse.ArgumentParser(description="Autobricks VPN 빌드")
    parser.add_argument("--release", action="store_true", help="최적화된 release 바이너리를 bin/에 배치")
    args = parser.parse_args()
    if not (MACOS or LINUX):
        raise RuntimeError("서버 빌드는 macOS와 Linux에서 지원합니다")
    prefix = wolfssl()
    stage(build_vpn(prefix, args.release), prefix)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"빌드 실패: {error}", file=sys.stderr)
        sys.exit(1)
