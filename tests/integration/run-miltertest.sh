#!/bin/sh
#
# signing-milter - tests/integration/run-miltertest.sh
# Run the miltertest Lua integration suite against a freshly built signing-milter.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${1:-$SRC_DIR/build}"

if [ ! -x "$BUILD_DIR/signing-milter" ]; then
    echo "ERROR: signing-milter binary not found at $BUILD_DIR/signing-milter"
    exit 1
fi

WORK_DIR="$(mktemp -d)"
MILTER_PID=""

cleanup() {
    if [ -n "$MILTER_PID" ]; then
        kill "$MILTER_PID" 2>/dev/null || true
        wait "$MILTER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

export MILTER_SOCKET="unix:$WORK_DIR/miltertest.sock"

# Generate a fresh test certificate and signingtable.cdb in the work directory.
"$SCRIPT_DIR/data/gen-test-cert.sh" "$WORK_DIR"

# Start the milter.  The current user is used so the test certificate remains
# readable after privilege dropping.  -c :relax opens the Unix socket with 0666.
"$BUILD_DIR/signing-milter" -u "$(id -un)" -g "$(id -gn)" -c :relax \
    -s "$MILTER_SOCKET" -m "$WORK_DIR/signingtable.cdb" -l -d 7 &
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

FAILED=0
for test in "$SCRIPT_DIR"/miltertest/*.lua; do
    echo "RUN $test"
    if miltertest -s "$test"; then
        echo "PASS $test"
    else
        echo "FAIL $test"
        FAILED=1
    fi
done

exit $FAILED
