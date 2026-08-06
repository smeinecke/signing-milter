#!/bin/sh
#
# signing-milter - tests/integration/data/gen-test-cert.sh
# Generate a small test CA, an end-entity signer certificate, and build the signingtable CDB.

set -e

OUTDIR="${1:-$(dirname "$0")}"
mkdir -p "$OUTDIR"

CA_KEY="$OUTDIR/test-ca-key.pem"
CA_PEM="$OUTDIR/test-ca.pem"
EE_KEY="$OUTDIR/test-ee-key.pem"
EE_CSR="$OUTDIR/test-ee.csr"
EE_CERT="$OUTDIR/test-ee-cert.pem"
COMBINED_PEM="$OUTDIR/test-cert+key.pem"
TABLE_TXT="$OUTDIR/signingtable"
TABLE_CDB="$OUTDIR/signingtable.cdb"

# Generate a small CA and an end-entity certificate signed by that CA.
# All OpenSSL files are created in OUTDIR so the CA serial file lands there.
(
    cd "$OUTDIR"

    # Root CA.
    openssl genpkey -algorithm RSA -out test-ca-key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl req -x509 -new -nodes -key test-ca-key.pem -sha256 -days 1 \
        -out test-ca.pem -subj "/CN=signing-milter test CA/O=Example" 2>/dev/null

    # End-entity signer certificate.
    openssl genpkey -algorithm RSA -out test-ee-key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl req -new -key test-ee-key.pem -out test-ee.csr \
        -subj "/CN=signing-milter test signer/O=Example" 2>/dev/null
    openssl x509 -req -in test-ee.csr -CA test-ca.pem -CAkey test-ca-key.pem \
        -CAcreateserial -out test-ee-cert.pem -days 1 -sha256 2>/dev/null
)

# signing-milter expects cert+key in a single PEM file.
cat "$EE_CERT" "$EE_KEY" > "$COMBINED_PEM"
chmod 0400 "$COMBINED_PEM"

rm -f "$CA_KEY" "$EE_KEY" "$EE_CSR" "$EE_CERT"

# Build the signing table.  The milter looks up the bare email address.
# The CDB format used by tinycdb is key<tab>value.
{
    printf 'sender@example.com\t%s\n' "$COMBINED_PEM"
    printf 'other@example.com\t%s\n' "$COMBINED_PEM"
} > "$TABLE_TXT"

cdb -c -m "$TABLE_CDB" "$TABLE_TXT"
