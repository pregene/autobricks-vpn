#!/bin/sh
set -eu

cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

exec python3 scripts/install.py "$@"
