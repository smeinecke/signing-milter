#!/bin/sh
#
# signing-milter - tests/integration/run-miltertest-auth.sh
# Run the milter integration suite against a milter configured with a local
# auth-signing table and X-Signer support.

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

# Build the auth-signing table.  One identity may have multiple signer values,
# either as multiple records or as a comma/whitespace-separated list.
AUTHSIGNINGTABLE_TXT="$WORK_DIR/authsigningtable"
AUTHSIGNINGTABLE_CDB="$WORK_DIR/authsigningtable.cdb"
{
    printf 'alice@example.org\tsender@example.com\n'
    printf 'alice@example.org\tsales@example.com\n'
    printf 'bob@example.org\tother@example.com\n'
    printf 'case@example.org\t<Sender@EXAMPLE.COM>, sales@example.com\n'
} > "$AUTHSIGNINGTABLE_TXT"
cdb -c -m "$AUTHSIGNINGTABLE_CDB" "$AUTHSIGNINGTABLE_TXT"

# Start the milter with the auth table and X-Signer enabled.
"$BUILD_DIR/signing-milter" -u "$(id -un)" -g "$(id -gn)" -c :relax \
    -s "$MILTER_SOCKET" -m "$SIGNINGTABLE_CDB" \
    -a "$AUTHSIGNINGTABLE_CDB" -f -l -d 7 &
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
    echo "ERROR: python3-miltertest is required for the auth integration tests"
    echo "       install it with: apt-get install python3-miltertest"
    exit 1
fi

FAILED=0
TEST="$SCRIPT_DIR/miltertest/auth-full-eom.py"
echo "RUN $TEST"
if MILTER_SOCKET="$MILTER_SOCKET" python3 -u "$TEST"; then
    echo "PASS $TEST"
else
    echo "FAIL $TEST"
    FAILED=1
fi

exit $FAILED
