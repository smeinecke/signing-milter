#!/bin/sh
#
# signing-milter - tests/integration/data/gen-test-cert.sh
# Generate a self-signed test certificate and build the signingtable CDB.

set -e

OUTDIR="${1:-$(dirname "$0")}"
mkdir -p "$OUTDIR"

CERT_PEM="$OUTDIR/test-cert.pem"
KEY_PEM="$OUTDIR/test-key.pem"
COMBINED_PEM="$OUTDIR/test-cert+key.pem"
TABLE_TXT="$OUTDIR/signingtable"
TABLE_CDB="$OUTDIR/signingtable.cdb"

# Generate a 2048 bit RSA key and a self-signed certificate valid for 1 day.
openssl genpkey -algorithm RSA -out "$KEY_PEM" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -x509 -key "$KEY_PEM" -out "$CERT_PEM" -days 1 \
    -subj "/CN=signing-milter test/O=Example" 2>/dev/null

# signing-milter expects cert+key in a single PEM file.
cat "$CERT_PEM" "$KEY_PEM" > "$COMBINED_PEM"
rm -f "$CERT_PEM" "$KEY_PEM"

# The daemon refuses PEM files that are writable or accessible by others.
chmod 0400 "$COMBINED_PEM"

# Build the signing table.  The milter looks up the bare email address.
# The CDB format used by tinycdb is key<tab>value.
{
    printf 'sender@example.com\t%s\n' "$COMBINED_PEM"
    printf 'other@example.com\t%s\n' "$COMBINED_PEM"
} > "$TABLE_TXT"

cdb -c -m "$TABLE_CDB" "$TABLE_TXT"
