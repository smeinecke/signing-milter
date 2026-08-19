#!/bin/sh
#
# signing-milter - tests/integration/run-miltertest-legacy.sh
# Run the milter integration suite against a milter using the legacy
# sender-address-only behavior (no -A, no -a, no -R).

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

# Generate a fresh test certificate and signing table.
"$SCRIPT_DIR/data/gen-test-cert.sh" "$WORK_DIR"

# Start the milter without any auth requirement.
"$BUILD_DIR/signing-milter" -u "$(id -un)" -g "$(id -gn)" -c :relax \
    -s "$MILTER_SOCKET" -m "$WORK_DIR/signingtable.cdb" \
    -f -l -d 7 &
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

if ! python3 -c "import miltertest" 2>/dev/null; then
    echo "ERROR: python3-miltertest is required for the legacy integration tests"
    echo "       install it with: apt-get install python3-miltertest"
    exit 1
fi

FAILED=0
TEST="$SCRIPT_DIR/miltertest/legacy-full-eom.py"
echo "RUN $TEST"
if MILTER_SOCKET="$MILTER_SOCKET" python3 -u "$TEST"; then
    echo "PASS $TEST"
else
    echo "FAIL $TEST"
    FAILED=1
fi

exit $FAILED
