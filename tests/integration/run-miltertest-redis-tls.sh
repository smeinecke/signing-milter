#!/bin/sh
#
# signing-milter - tests/integration/run-miltertest-redis-tls.sh
# End-to-end Redis TLS tests for signing-milter.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${1:-$SRC_DIR/build}"

if [ ! -x "$BUILD_DIR/signing-milter" ]; then
    echo "ERROR: signing-milter binary not found at $BUILD_DIR/signing-milter"
    exit 1
fi

if ! command -v redis-server >/dev/null 2>&1 || ! command -v redis-cli >/dev/null 2>&1; then
    echo "SKIP: redis-server and redis-cli are required"
    exit 0
fi

export BUILD_DIR
python3 "$SCRIPT_DIR/miltertest/redis-tls-test.py"
