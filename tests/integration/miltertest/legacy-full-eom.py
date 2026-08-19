#!/usr/bin/env python3
"""
signing-milter - tests/integration/miltertest/legacy-full-eom.py
Full end-of-message integration tests for the legacy unauthenticated
sender-address behavior (no -A, no -a, no -R).

The milter under test must be started with:
  -f
  -m <signingtable.cdb>
  no -a, no -R, and no -A
and the MILTER_SOCKET environment variable must point to its socket.
"""

import os
import socket
import sys

sys.path.insert(0, "/usr/lib/python3/dist-packages")

from miltertest import client, constants

MILTER_SOCKET = os.environ.get("MILTER_SOCKET", "unix:/tmp/signing-milter-test/miltertest.sock")
if MILTER_SOCKET.startswith("unix:"):
    MILTER_SOCKET = MILTER_SOCKET[5:]


def _send_headers(mc, headers):
    for name, value in headers:
        r = mc.send_ar(constants.SMFIC_HEADER, name=name, value=value)
        if r[0] not in client.DISPOSITION_REPLIES:
            raise AssertionError(f"unexpected header reply for {name}: {r}")


def run_transaction(auth_identity, envfrom, xsigner=None,
                    expect_signed=True, expect_xsigner_deleted=False,
                    xsigners=None):
    """Run a single milter transaction and assert on signing and header deletion."""

    body = "This is a test message.\r\n"
    body_replaced = False
    content_type_added = False
    xsigner_deleted_count = 0

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(MILTER_SOCKET)
    mc = client.MilterConnection(sock)
    mc.optneg_mta()

    if auth_identity:
        mc.send_macro(constants.SMFIC_MAIL, **{"{auth_authen}": auth_identity})

    r = mc.send_get(constants.SMFIC_MAIL, args=[envfrom])
    if r[0] not in client.DISPOSITION_REPLIES:
        raise AssertionError(f"unexpected mailfrom reply: {r}")
    if r[0] == constants.SMFIR_ACCEPT:
        if expect_signed:
            raise AssertionError(f"expected signing but got ACCEPT for auth={auth_identity}, envfrom={envfrom}")
        sock.close()
        return

    r = mc.send_get(constants.SMFIC_RCPT, args=["<recipient@example.com>"])
    if r[0] not in client.DISPOSITION_REPLIES:
        raise AssertionError(f"unexpected rcpt reply: {r}")
    if r[0] == constants.SMFIR_ACCEPT:
        if expect_signed:
            raise AssertionError(f"expected signing but got ACCEPT for auth={auth_identity}, envfrom={envfrom}")
        sock.close()
        return

    headers = [
        ("From", envfrom),
        ("To", "<recipient@example.com>"),
        ("Subject", "legacy signing test"),
    ]
    if xsigner:
        headers.append(("X-Signer", xsigner))
    if xsigners:
        for xs in xsigners:
            headers.append(("X-Signer", xs))
    _send_headers(mc, headers)

    r = mc.send_get(constants.SMFIC_EOH)
    if r[0] not in client.DISPOSITION_REPLIES:
        raise AssertionError(f"unexpected eoh reply: {r}")
    if r[0] == constants.SMFIR_ACCEPT:
        if expect_signed:
            raise AssertionError(f"expected signing but got ACCEPT at EOH for auth={auth_identity}, envfrom={envfrom}")
        sock.close()
        return

    mc.send_body(body)

    res = mc.send_eom()
    for cmd, data in res:
        if cmd == constants.SMFIR_REPLBODY:
            body_replaced = True
        if cmd == constants.SMFIR_ADDHEADER and data.get("name") == "Content-Type":
            content_type_added = True
        if (
            cmd == constants.SMFIR_CHGHEADER
            and data.get("name") == "X-Signer"
            and data.get("value") == ""
        ):
            xsigner_deleted_count += 1

    sock.close()

    signed = body_replaced and content_type_added
    if expect_signed and not signed:
        raise AssertionError(
            f"expected message to be signed for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner} "
            f"(body_replaced={body_replaced}, content_type_added={content_type_added})"
        )

    if not expect_signed and signed:
        raise AssertionError(
            f"expected message NOT to be signed for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner} "
            f"(body_replaced={body_replaced}, content_type_added={content_type_added})"
        )

    if expect_xsigner_deleted and xsigner_deleted_count == 0:
        raise AssertionError(
            f"expected X-Signer header to be deleted for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner}"
        )

    if not expect_xsigner_deleted and xsigner_deleted_count > 0:
        raise AssertionError(
            f"did not expect X-Signer header to be deleted for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner}"
        )


def main():
    # 1. Unauthenticated mail from a known envelope sender is signed.
    print("test 1: legacy signs known envelope sender without auth")
    run_transaction(None, "<sender@example.com>", expect_signed=True)

    # 2. Unauthenticated mail from an unknown envelope sender is not signed.
    print("test 2: legacy does not sign unknown envelope sender")
    run_transaction(None, "<unknown@example.com>", expect_signed=False)

    # 3. X-Signer can override an unknown envelope sender in legacy mode.
    print("test 3: legacy X-Signer override")
    run_transaction(
        None,
        "<unknown@example.com>",
        xsigner="other@example.com",
        expect_signed=True,
        expect_xsigner_deleted=True,
    )

    # 4. Authenticated identity is ignored in legacy mode; the signingtable wins.
    print("test 4: legacy ignores auth identity, signs known sender")
    run_transaction("mallory@evil.example", "<sender@example.com>", expect_signed=True)

    # 5. Duplicate X-Signer is ignored and all occurrences are deleted.
    print("test 5: legacy duplicate X-Signer ignored, first used")
    run_transaction(
        None,
        "<unknown@example.com>",
        xsigners=["sender@example.com", "other@example.com"],
        expect_signed=True,
        expect_xsigner_deleted=True,
    )

    print("PASS")


if __name__ == "__main__":
    main()
