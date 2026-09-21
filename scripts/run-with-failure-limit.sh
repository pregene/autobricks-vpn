#!/bin/sh
set -u

if [ "$#" -eq 0 ]; then
  echo "usage: $0 command [arguments...]" >&2
  exit 2
fi

attempt=1
child=
stop() {
  if [ -n "$child" ]; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  exit 0
}
trap stop INT TERM

while [ "$attempt" -le 5 ]; do
  "$@" &
  child=$!
  wait "$child"
  status=$?
  child=
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  echo "autobricks-vpn: attempt $attempt/5 failed (status $status)" >&2
  attempt=$((attempt + 1))
done

exit "$status"
