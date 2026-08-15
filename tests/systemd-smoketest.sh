#!/bin/sh
#
# signing-milter - tests/systemd-smoketest.sh
# Smoke test: start signing-milter under systemd and verify it becomes active.

set -e

SOCKET="/var/spool/postfix/signing-milter/signing-milter.sock"

log() {
    echo "[systemd-smoketest] $*"
}

log "waiting for systemd to be ready"
for i in $(seq 1 30); do
    if systemctl is-system-running >/dev/null 2>&1; then
        log "systemd is running"
        break
    fi
    sleep 1
done

log "starting signing-milter.service"
systemctl start signing-milter

log "waiting for service to become active"
for i in $(seq 1 30); do
    if systemctl is-active signing-milter >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! systemctl is-active signing-milter >/dev/null 2>&1; then
    log "service is not active"
    systemctl status signing-milter --no-pager || true
    journalctl -u signing-milter -n 50 --no-pager || true
    exit 1
fi

log "service is active"
systemctl status signing-milter --no-pager

if [ ! -S "$SOCKET" ]; then
    log "milter socket $SOCKET not found"
    exit 1
fi

ls -l "$SOCKET"
log "systemd smoke test passed"
