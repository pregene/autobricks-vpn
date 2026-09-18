#!/bin/sh
set -eu

if [ -z "${WOLFSSL_PREFIX:-}" ]; then
    echo "WOLFSSL_PREFIX must point to the project wolfSSL build." >&2
    exit 2
fi

FEATURES="${AUTOBRICKS_VPN_FEATURES:-dtls13}"

cargo fmt --all -- --check
cargo test --features "$FEATURES" panic_gate -- --nocapture --test-threads=1
cargo test --features "$FEATURES"
cargo clippy --all-targets --features "$FEATURES" -- -D warnings
git diff --check
