#!/bin/sh
#
# signing-milter - tests/integration/run-miltertest-auth-redis.sh
# Run the milter integration suite against a milter using the Redis-backed
# auth-signing table.  Requires python3-miltertest and a local redis-server.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${1:-$SRC_DIR/build}"

if [ ! -x "$BUILD_DIR/signing-milter" ]; then
    echo "ERROR: signing-milter binary not found at $BUILD_DIR/signing-milter"
    exit 1
fi

if ! command -v redis-server >/dev/null 2>&1; then
    echo "ERROR: redis-server is required for the Redis auth integration test"
    exit 1
fi

if ! python3 -c "import miltertest" 2>/dev/null; then
    echo "ERROR: python3-miltertest is required for the auth integration tests"
    echo "       install it with: apt-get install python3-miltertest"
    exit 1
fi

WORK_DIR="$(mktemp -d)"
MILTER_PID=""
REDIS_PID=""

cleanup() {
    if [ -n "$MILTER_PID" ]; then
        kill "$MILTER_PID" 2>/dev/null || true
        wait "$MILTER_PID" 2>/dev/null || true
    fi
    if [ -n "$REDIS_PID" ]; then
        redis-cli -s "$REDIS_SOCK" SHUTDOWN NOSAVE >/dev/null 2>&1 || true
        wait "$REDIS_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

export MILTER_SOCKET="unix:$WORK_DIR/miltertest.sock"
REDIS_SOCK="$WORK_DIR/redis.sock"
REDIS_PREFIX="signing-milter:"

# Generate a fresh test certificate and base signing table.
"$SCRIPT_DIR/data/gen-test-cert.sh" "$WORK_DIR"

# Extend the signing table so the auth tests can exercise several signer
# identities that all share the single generated PEM file.
SIGNINGTABLE_TXT="$WORK_DIR/signingtable"
SIGNINGTABLE_CDB="$WORK_DIR/signingtable.cdb"
CERT="$WORK_DIR/test-cert+key.pem"
{
    printf 'sales@example.com\t%s\n' "$CERT"
    printf 'third@example.com\t%s\n' "$CERT"
} >> "$SIGNINGTABLE_TXT"
cdb -c -m "$SIGNINGTABLE_CDB" "$SIGNINGTABLE_TXT"

# Start a private Redis instance on a unix socket.
rm -f "$REDIS_SOCK"
redis-server --port 0 --unixsocket "$REDIS_SOCK" --daemonize yes
sleep 0.5

# Populate the Redis auth-signing table.  Keys are <prefix>auth:<identity> and
# contain the set of permitted signing identities.
redis-cli -s "$REDIS_SOCK" SADD "${REDIS_PREFIX}auth:alice@example.org" sender@example.com
redis-cli -s "$REDIS_SOCK" SADD "${REDIS_PREFIX}auth:alice@example.org" sales@example.com
redis-cli -s "$REDIS_SOCK" SADD "${REDIS_PREFIX}auth:bob@example.org" other@example.com
redis-cli -s "$REDIS_SOCK" SADD "${REDIS_PREFIX}auth:case@example.org" "<Sender@EXAMPLE.COM>" sales@example.com

# Start the milter with the Redis auth table and X-Signer enabled.
"$BUILD_DIR/signing-milter" -u "$(id -un)" -g "$(id -gn)" -c :relax \
    -s "$MILTER_SOCKET" -m "$SIGNINGTABLE_CDB" \
    -R -r "unix:$REDIS_SOCK" -P "$REDIS_PREFIX" -f -l -d 7 &
MILTER_PID=$!

# Wait for the socket to appear.
for i in $(seq 1 30); do
    if [ -S "$WORK_DIR/miltertest.sock" ]; then
        break
    fi
    sleep 0.5
done
if [ ! -S "$WORK_DIR/miltertest.sock" ]; then
    echo "ERROR: signing-milter did not create socket"
    exit 1
fi

TEST="$SCRIPT_DIR/miltertest/auth-full-eom.py"
echo "RUN $TEST (Redis)"
if MILTER_SOCKET="$MILTER_SOCKET" python3 -u "$TEST"; then
    echo "PASS $TEST"
else
    echo "FAIL $TEST"
    exit 1
fi
