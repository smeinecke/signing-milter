#!/bin/sh
#
# signing-milter - tests/integration/run-postfix.sh
# End-to-end integration test: run signing-milter with a real Postfix instance,
# send a message via SMTP, and verify the delivered message is S/MIME signed.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${1:-$SRC_DIR/build}"

if [ ! -x "$BUILD_DIR/signing-milter" ]; then
    echo "ERROR: signing-milter binary not found at $BUILD_DIR/signing-milter"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this script must run as root to start Postfix"
    exit 1
fi

WORK_DIR="$(mktemp -d)"
MILTER_USER="test"
MILTER_SOCKET="inet:30053@127.0.0.1"
POSTFIX_MILTER_SOCKET="inet:127.0.0.1:30053"
MILTER_PID=""
POSTFIX_STARTED=""

log() {
    echo "[run-postfix] $*"
}

cleanup() {
    _exit_status=$?
    if [ "$_exit_status" -ne 0 ]; then
        log "exit status $_exit_status; printing logs for debugging"
        if [ -f "$WORK_DIR/milter.log" ]; then
            echo "--- signing-milter log ---"
            cat "$WORK_DIR/milter.log" || true
        fi
        if [ -f /var/log/mail.log ]; then
            echo "--- Postfix log ---"
            cat /var/log/mail.log || true
        fi
    fi
    log "cleaning up ..."
    if [ -n "$POSTFIX_STARTED" ]; then
        postfix stop 2>/dev/null || true
    fi
    if [ -n "$MILTER_PID" ]; then
        kill "$MILTER_PID" 2>/dev/null || true
        wait "$MILTER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Make the work directory accessible to the unprivileged milter user.
chmod 0755 "$WORK_DIR"

# Generate test CA, signer certificate, signing table as root and hand
# ownership over to the milter user.  The daemon drops privileges itself.
"$SCRIPT_DIR/data/gen-test-cert.sh" "$WORK_DIR"
chown -R "$MILTER_USER:$MILTER_USER" "$WORK_DIR"

# Verify the generated certificate is actually usable as a CA.
if [ ! -f "$WORK_DIR/test-ca.pem" ]; then
    echo "ERROR: test CA not generated"
    exit 1
fi

# Prepare the test user's Maildir. Postfix will deliver there.
MILTER_HOME="$(getent passwd "$MILTER_USER" | cut -d: -f6)"
MAILDIR="$MILTER_HOME/Maildir"
mkdir -p "$MAILDIR/new" "$MAILDIR/cur" "$MAILDIR/tmp"
chown -R "$MILTER_USER:$MILTER_USER" "$MAILDIR"

# Configure Postfix minimally for a local loopback test.
postconf -e "myhostname = test.example.com"
postconf -e "mydomain = example.com"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, \$mydomain, localhost"
postconf -e "inet_interfaces = 127.0.0.1"
postconf -e "mynetworks = 127.0.0.0/8"
postconf -e "home_mailbox = Maildir/"
postconf -e "smtpd_milters = $POSTFIX_MILTER_SOCKET"
postconf -e "milter_default_action = accept"
postconf -e "maillog_file = /var/log/mail.log"
postconf -e "smtpd_delay_reject = no"

# Fix Postfix permissions in case the install did not set them up.
postfix set-permissions 2>/dev/null || true

# Start signing-milter as root; it will setuid/setgid to the configured
# user itself.  The log file is opened here as root and the daemon keeps
# the inherited descriptor after dropping privileges.
log "starting signing-milter on $MILTER_SOCKET ..."
stdbuf -oL -eL "$BUILD_DIR/signing-milter" \
    -u "$MILTER_USER" -g "$MILTER_USER" \
    -s "$MILTER_SOCKET" -m "$WORK_DIR/signingtable.cdb" -l -d 7 \
    > "$WORK_DIR/milter.log" 2>&1 &
MILTER_PID=$!

# Wait for the milter to listen on port 30053.
for i in $(seq 1 30); do
    if ss -H -l -t -n | grep -q ':30053'; then
        log "signing-milter is listening"
        break
    fi
    sleep 0.2
done
if ! ss -H -l -t -n | grep -q ':30053'; then
    echo "ERROR: signing-milter did not start"
    cat "$WORK_DIR/milter.log" || true
    exit 1
fi

# Start Postfix.
log "starting Postfix ..."
postfix start
POSTFIX_STARTED=1

# Wait for the SMTP listener on port 25.
for i in $(seq 1 30); do
    if ss -H -l -t -n | grep -q ':25 '; then
        log "Postfix is listening"
        break
    fi
    sleep 0.2
done
if ! ss -H -l -t -n | grep -q ':25 '; then
    echo "ERROR: Postfix did not start"
    cat /var/log/mail.log 2>/dev/null || true
    cat "$WORK_DIR/milter.log" || true
    exit 1
fi

# Send a test message from the address present in the signing table.
log "sending test message ..."
swaks --to test@localhost --from sender@example.com --server 127.0.0.1 --port 25 \
    --body "$SCRIPT_DIR/data/message-plain.txt" \
    --h-Subject "signing-milter Postfix integration test"

# Wait for the message to be delivered.
DELIVERED=""
for i in $(seq 1 60); do
    DELIVERED="$(find "$MAILDIR/new" -type f 2>/dev/null | head -n1)"
    if [ -n "$DELIVERED" ]; then
        break
    fi
    sleep 0.5
done

if [ -z "$DELIVERED" ]; then
    echo "ERROR: message was not delivered"
    cat /var/log/mail.log 2>/dev/null || true
    cat "$WORK_DIR/milter.log" || true
    exit 1
fi

log "delivered message: $DELIVERED"
cp "$DELIVERED" "$WORK_DIR/delivered.eml"

# Structural validation.
if ! grep -q "^[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Tt][Yy][Pp][Ee]:[[:space:]]*multipart/signed" "$WORK_DIR/delivered.eml"; then
    echo "ERROR: delivered message is not multipart/signed"
    cat "$WORK_DIR/delivered.eml"
    exit 1
fi
if ! grep -qi "pkcs7-signature" "$WORK_DIR/delivered.eml"; then
    echo "ERROR: no pkcs7-signature part found"
    cat "$WORK_DIR/delivered.eml"
    exit 1
fi
log "PASS: delivered message is S/MIME multipart/signed"

# Cryptographic validation against the generated CA.
if ! openssl smime -verify -in "$WORK_DIR/delivered.eml" -CAfile "$WORK_DIR/test-ca.pem" -out /dev/null; then
    echo "ERROR: S/MIME verification failed"
    cat /var/log/mail.log 2>/dev/null || true
    cat "$WORK_DIR/milter.log" || true
    exit 1
fi
log "PASS: S/MIME signature verified"
