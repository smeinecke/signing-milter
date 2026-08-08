#!/bin/sh
#
# signing-milter - tests/integration/run-redis-test.sh
# End-to-end integration test using Redis as the certificate backend.
#
# The script can be used in two modes:
#   - standalone: it starts a temporary redis-server itself
#   - docker compose: the Redis host is provided via REDIS_HOST or REDIS_URI
#
# Example:
#   REDIS_HOST=redis tests/integration/run-redis-test.sh build

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
REDIS_PID=""
REDIS_URI="${REDIS_URI:-}"
REDIS_HOST="${REDIS_HOST:-}"
REDIS_SOCKET=""

# Helper for redis-cli calls depending on the URI type.
redis_cli() {
    case "$REDIS_URI" in
        unix:*)
            _sock="${REDIS_URI#unix:}"
            _sock="${_sock#//}"
            redis-cli -s "$_sock" "$@"
            ;;
        rediss://*)
            redis-cli -u "$REDIS_URI" --tls "$@"
            ;;
        *)
            redis-cli -u "$REDIS_URI" "$@"
            ;;
    esac
}

log() {
    echo "[run-redis-test] $*"
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
        if [ -n "$REDIS_PID" ] && [ -f "$WORK_DIR/redis.log" ]; then
            echo "--- Redis log ---"
            cat "$WORK_DIR/redis.log" || true
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
    if [ -n "$REDIS_PID" ]; then
        kill "$REDIS_PID" 2>/dev/null || true
        wait "$REDIS_PID" 2>/dev/null || true
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

# signing-milter now requires an auth-signing table.  The XCLIENT LOGIN below
# tells Postfix to report the authenticated identity "testuser".
AUTHSIGNINGTABLE_TXT="$WORK_DIR/authsigningtable"
AUTHSIGNINGTABLE_CDB="$WORK_DIR/authsigningtable.cdb"
printf 'testuser\tsender@example.com\n' > "$AUTHSIGNINGTABLE_TXT"
cdb -c -m "$AUTHSIGNINGTABLE_CDB" "$AUTHSIGNINGTABLE_TXT"

# Verify the generated certificate is actually usable as a CA.
if [ ! -f "$WORK_DIR/test-ca.pem" ]; then
    echo "ERROR: test CA not generated"
    exit 1
fi

# Determine Redis URI and wait for it to be reachable.
if [ -n "$REDIS_URI" ]; then
    log "using Redis URI from environment"
elif [ -n "$REDIS_HOST" ]; then
    REDIS_URI="redis://$REDIS_HOST:6379/0"
else
    log "starting local redis-server ..."
    REDIS_SOCKET="$WORK_DIR/redis.sock"
    redis-server --daemonize no \
        --unixsocket "$REDIS_SOCKET" \
        --unixsocketperm 777 \
        --port 0 \
        --dir "$WORK_DIR" \
        --logfile "$WORK_DIR/redis.log" \
        --pidfile "$WORK_DIR/redis.pid" &
    REDIS_PID=$!
    REDIS_URI="unix:$REDIS_SOCKET"
fi

for i in $(seq 1 30); do
    if redis_cli -n 0 PING 2>/dev/null | grep -q PONG; then
        log "redis at $REDIS_URI is ready"
        break
    fi
    sleep 0.2
done
if ! redis_cli -n 0 PING 2>/dev/null | grep -q PONG; then
    echo "ERROR: redis at $REDIS_URI is not reachable"
    exit 1
fi

# Make sure the test database is empty in case the Redis instance is reused.
redis_cli -n 0 FLUSHDB

# Seed Redis with the generated certificate.
log "seeding Redis with test certificate (URI: $REDIS_URI) ..."
redis_cli -n 0 HMSET "signing-milter:sender@example.com" \
    pem "$(cat "$WORK_DIR/test-cert+key.pem")" \
    chain "$(cat "$WORK_DIR/test-ca.pem")"

# Optional: a second sender with the same key and no chain.
redis_cli -n 0 HMSET "signing-milter:other@example.com" \
    pem "$(cat "$WORK_DIR/test-cert+key.pem")"

# Prepare the test user's Maildir. Postfix will deliver there.
# Clean it first: the Docker image build may have left a test message there,
# and find ... | head -n1 would otherwise pick the wrong (stale) mail.
MILTER_HOME="$(getent passwd "$MILTER_USER" | cut -d: -f6)"
MAILDIR="$MILTER_HOME/Maildir"
rm -rf "$MAILDIR"
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
postconf -e "smtpd_authorized_xclient_hosts = 127.0.0.0/8"

# Fix Postfix permissions in case the install did not set them up.
postfix set-permissions 2>/dev/null || true

# Start signing-milter as root; it will setuid/setgid to the configured
# user itself.  Use Redis as the certificate source, no CDB signingtable.
log "starting signing-milter on $MILTER_SOCKET with Redis ..."
stdbuf -oL -eL "$BUILD_DIR/signing-milter" \
    -u "$MILTER_USER" -g "$MILTER_USER" \
    -s "$MILTER_SOCKET" -r "$REDIS_URI" -P "signing-milter:" \
    -a "$AUTHSIGNINGTABLE_CDB" -l -d 7 \
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

# Send a test message from the address present in Redis.
log "sending test message ..."
swaks --to test@localhost --from sender@example.com --server 127.0.0.1 --port 25 \
    --xclient-addr 127.0.0.1 --xclient-name localhost --xclient-login testuser \
    --body "$SCRIPT_DIR/data/message-plain.txt" \
    --h-Subject "signing-milter Redis integration test"

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
log "PASS: S/MIME signature verified via Redis"
