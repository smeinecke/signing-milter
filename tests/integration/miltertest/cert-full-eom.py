#!/usr/bin/env python3
"""
signing-milter - tests/integration/miltertest/cert-full-eom.py
Full end-of-message integration tests for certificate-CN fallback authorization.

The milter under test must be started with:
  -f
  -m <signingtable.cdb>
  no -a and no -R
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
                    signer_override=False):
    """Run a single milter transaction and assert on signing and header deletion."""

    body = "This is a test message.\r\n"
    body_replaced = False
    content_type_added = False
    xsigner_deleted = False

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
        ("Subject", "cert fallback test"),
    ]
    if xsigner:
        headers.append(("X-Signer", xsigner))
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
            xsigner_deleted = True

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

    if expect_xsigner_deleted and not xsigner_deleted:
        raise AssertionError(
            f"expected X-Signer header to be deleted for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner}"
        )

    if not expect_xsigner_deleted and xsigner_deleted:
        raise AssertionError(
            f"did not expect X-Signer header to be deleted for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner}"
        )


def main():
    # 1. Authenticated user matches the certificate CN.
    print("test 1: CN matches auth_authen")
    run_transaction("alice", "<alice@example.org>", expect_signed=True)

    # 2. Case-sensitive comparison; CN is "alice" but auth is "Alice".
    print("test 2: CN case mismatch denied")
    run_transaction("Alice", "<alice@example.org>", expect_signed=False)

    # 3. Missing authenticated identity.
    print("test 3: missing auth_authen denied")
    run_transaction(None, "<alice@example.org>", expect_signed=False)

    # 4. Envelope signer certificate has a different CN ("nobody").
    print("test 4: envelope signer CN mismatch, no X-Signer")
    run_transaction("alice", "<third@example.com>", expect_signed=False)

    # 5. X-Signer override with a certificate CN matching the auth identity.
    print("test 5: X-Signer override with matching CN")
    run_transaction(
        "alice",
        "<third@example.com>",
        xsigner="<alice@example.org>",
        expect_signed=True,
        expect_xsigner_deleted=True,
        signer_override=True,
    )

    # 6. Authorized envelope signer + unauthorized X-Signer.
    #    X-Signer cert CN is "bob"; auth identity is "alice".  The envelope
    #    signer cert CN is "alice", so the message must still be signed.
    print("test 6: envelope signer authorized, X-Signer ignored")
    run_transaction(
        "alice",
        "<alice@example.org>",
        xsigner="<other@example.com>",
        expect_signed=True,
        expect_xsigner_deleted=True,
    )

    print("PASS")


if __name__ == "__main__":
    main()
