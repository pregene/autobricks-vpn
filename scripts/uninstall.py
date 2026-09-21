#!/usr/bin/env python3
"""Remove services and runtime files installed by install.sh."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


PREFIX = Path("/opt/autobricks-vpn")
CONFIG_DIR = Path("/etc/autobricks-vpn")
LAUNCH_DIR = Path("/Library/LaunchDaemons")
SYSTEMD_DIR = Path("/etc/systemd/system")
LDCONFIG_FILE = Path("/etc/ld.so.conf.d/autobricks-vpn.conf")
LABELS = ("kr.co.autobricks.vpn-web", "kr.co.autobricks.vpn-server")
UNITS = ("autobricks-vpn-web.service", "autobricks-vpn.service")


def command(*args, required=True):
    print("+", " ".join(map(str, args)), flush=True)
    result = subprocess.run(args, check=False)
    if result.returncode:
        if required:
            raise RuntimeError(f"서비스를 중지하거나 갱신하지 못했습니다: {' '.join(map(str, args))}")
        print(f"  종료 코드 {result.returncode}; 계속 진행합니다.", file=sys.stderr)


def remove_macos_services():
    for label in LABELS:
        plist = LAUNCH_DIR / f"{label}.plist"
        if plist.is_file():
            loaded = subprocess.run(["launchctl", "print", f"system/{label}"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    check=False).returncode == 0
            if loaded:
                command("launchctl", "bootout", "system", str(plist))
            plist.unlink()
            print("제거:", plist)


def remove_linux_services():
    for unit in UNITS:
        path = SYSTEMD_DIR / unit
        if path.is_file():
            command("systemctl", "stop", unit)
            command("systemctl", "disable", unit, required=False)
            path.unlink()
            print("제거:", path)
    if LDCONFIG_FILE.is_file() and LDCONFIG_FILE.read_text().strip() == str(PREFIX / "bin"):
        LDCONFIG_FILE.unlink()
        print("제거:", LDCONFIG_FILE)
    command("systemctl", "daemon-reload")
    command("ldconfig")


def remove_files(purge):
    data = PREFIX / "web/data"
    if not purge and data.exists():
        if data.is_symlink():
            raise RuntimeError(f"웹 데이터 경로가 심볼릭 링크입니다: {data}")
        saved = CONFIG_DIR / "web-data"
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(data, saved, dirs_exist_ok=True)
        print("웹 이벤트 데이터 보존:", saved)
    if PREFIX.is_symlink():
        raise RuntimeError(f"설치 경로가 심볼릭 링크입니다: {PREFIX}")
    if PREFIX.is_dir():
        shutil.rmtree(PREFIX)
        print("제거:", PREFIX)
    if purge and CONFIG_DIR.is_dir():
        if CONFIG_DIR.is_symlink():
            raise RuntimeError(f"설정 경로가 심볼릭 링크입니다: {CONFIG_DIR}")
        shutil.rmtree(CONFIG_DIR)
        print("설정·인증서 영구 삭제:", CONFIG_DIR)


def main():
    parser = argparse.ArgumentParser(description="Autobricks VPN 서버 제거")
    parser.add_argument("--purge", action="store_true",
                        help="설정, 인증서, Root CA 개인키, 웹 이벤트 데이터까지 영구 삭제")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("sudo 권한이 필요합니다")
    if sys.platform == "darwin":
        remove_macos_services()
    elif sys.platform.startswith("linux"):
        remove_linux_services()
    else:
        raise RuntimeError("서버 제거는 macOS와 Linux만 지원합니다")
    remove_files(args.purge)
    if not args.purge:
        print("설정과 인증서는 보존했습니다:", CONFIG_DIR)
    print("제거 완료. 저장소의 dependens/ 빌드 캐시는 유지됩니다.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f"제거 실패: {error}", file=sys.stderr)
        sys.exit(1)
