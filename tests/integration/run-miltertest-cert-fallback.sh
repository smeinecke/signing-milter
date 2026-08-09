#!/bin/sh
#
# signing-milter - tests/integration/run-miltertest-cert-fallback.sh
# Run the milter integration suite against a milter using certificate-CN
# fallback authorization (no -a / -R configured).

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

# Build a tiny CA for signing the test certificates.
CA_KEY="$WORK_DIR/test-ca-key.pem"
CA_PEM="$WORK_DIR/test-ca.pem"
openssl genpkey -algorithm RSA -out "$CA_KEY" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 1 \
    -out "$CA_PEM" -subj "/CN=signing-milter test CA/O=Example" 2>/dev/null

gen_cert() {
    local name="$1"
    local cn="$2"
    local key="$WORK_DIR/${name}-key.pem"
    local csr="$WORK_DIR/${name}.csr"
    local cert="$WORK_DIR/${name}-cert.pem"
    local combined="$WORK_DIR/${name}-cert+key.pem"

    openssl genpkey -algorithm RSA -out "$key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl req -new -key "$key" -out "$csr" \
        -subj "/CN=${cn}/O=Example" 2>/dev/null
    openssl x509 -req -in "$csr" -CA "$CA_PEM" -CAkey "$CA_KEY" \
        -CAcreateserial -out "$cert" -days 1 -sha256 2>/dev/null
    cat "$cert" "$key" > "$combined"
    chmod 0400 "$combined"
    printf '%s\n' "$combined"
}

ALICE_CERT="$(gen_cert alice alice)"
BOB_CERT="$(gen_cert bob bob)"
THIRD_CERT="$(gen_cert third nobody)"

rm -f "$WORK_DIR"/*.csr

# Build the signing table.  The CN in each certificate acts as the SASL
# principal for certificate-CN fallback authorization.
SIGNINGTABLE_TXT="$WORK_DIR/signingtable"
SIGNINGTABLE_CDB="$WORK_DIR/signingtable.cdb"
{
    printf 'alice@example.org\t%s\n' "$ALICE_CERT"
    printf 'bob@example.org\t%s\n' "$BOB_CERT"
    printf 'other@example.com\t%s\n' "$BOB_CERT"
    printf 'third@example.com\t%s\n' "$THIRD_CERT"
} > "$SIGNINGTABLE_TXT"
cdb -c -m "$SIGNINGTABLE_CDB" "$SIGNINGTABLE_TXT"

# Start the milter without any auth-signing table.
"$BUILD_DIR/signing-milter" -u "$(id -un)" -g "$(id -gn)" -c :relax \
    -s "$MILTER_SOCKET" -m "$SIGNINGTABLE_CDB" \
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
    echo "ERROR: python3-miltertest is required for the auth integration tests"
    echo "       install it with: apt-get install python3-miltertest"
    exit 1
fi

FAILED=0
TEST="$SCRIPT_DIR/miltertest/cert-full-eom.py"
echo "RUN $TEST"
if MILTER_SOCKET="$MILTER_SOCKET" python3 -u "$TEST"; then
    echo "PASS $TEST"
else
    echo "FAIL $TEST"
    FAILED=1
fi

exit $FAILED
