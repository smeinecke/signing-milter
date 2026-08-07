#!/usr/bin/env python3
"""
 signing-milter - tests/integration/miltertest/auth-full-eom.py
 Full end-of-message integration tests for the auth-signing-table feature,
 using the python3-miltertest package.

 The milter under test must be started with:
   -a <authsigningtable.cdb>
   -f
   -m <signingtable.cdb>
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


def _assert_signed(state, auth_identity, envfrom, xsigner):
    if state["expect_signed"] and not (state["body_replaced"] and state["content_type_added"]):
        raise AssertionError(
            f"expected message to be signed for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner} "
            f"(body_replaced={state['body_replaced']}, "
            f"content_type_added={state['content_type_added']})"
        )

    if not state["expect_signed"] and (state["body_replaced"] or state["content_type_added"]):
        raise AssertionError(
            f"expected message NOT to be signed for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner} "
            f"(body_replaced={state['body_replaced']}, "
            f"content_type_added={state['content_type_added']})"
        )

    if state["expect_xsigner_deleted"] and not state["xsigner_deleted"]:
        raise AssertionError(
            f"expected X-Signer header to be deleted for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner}"
        )

    if not state["expect_xsigner_deleted"] and state["xsigner_deleted"]:
        raise AssertionError(
            f"did not expect X-Signer header to be deleted for auth={auth_identity}, "
            f"envfrom={envfrom}, xsigner={xsigner}"
        )


def run_transaction(auth_identity, envfrom, xsigner=None, expect_signed=True, expect_xsigner_deleted=False):
    """Run a single milter transaction and assert on signing and header deletion."""

    body = "This is a test message.\r\n"
    state = {
        "expect_signed": expect_signed,
        "expect_xsigner_deleted": expect_xsigner_deleted,
        "body_replaced": False,
        "content_type_added": False,
        "xsigner_deleted": False,
    }

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
        _assert_signed(state, auth_identity, envfrom, xsigner)
        sock.close()
        return

    r = mc.send_get(constants.SMFIC_RCPT, args=["<recipient@example.com>"])
    if r[0] not in client.DISPOSITION_REPLIES:
        raise AssertionError(f"unexpected rcpt reply: {r}")
    if r[0] == constants.SMFIR_ACCEPT:
        _assert_signed(state, auth_identity, envfrom, xsigner)
        sock.close()
        return

    headers = [
        ("From", envfrom),
        ("To", "<recipient@example.com>"),
        ("Subject", "auth-signing test"),
    ]
    if xsigner:
        headers.append(("X-Signer", xsigner))
    _send_headers(mc, headers)

    r = mc.send_get(constants.SMFIC_EOH)
    if r[0] not in client.DISPOSITION_REPLIES:
        raise AssertionError(f"unexpected eoh reply: {r}")
    if r[0] == constants.SMFIR_ACCEPT:
        # milter decided not to sign before body processing
        _assert_signed(state, auth_identity, envfrom, xsigner)
        sock.close()
        return

    mc.send_body(body)

    res = mc.send_eom()
    for cmd, data in res:
        if cmd == constants.SMFIR_REPLBODY:
            state["body_replaced"] = True
        if cmd == constants.SMFIR_ADDHEADER and data.get("name") == "Content-Type":
            state["content_type_added"] = True
        if (
            cmd == constants.SMFIR_CHGHEADER
            and data.get("name") == "X-Signer"
            and data.get("value") == ""
        ):
            state["xsigner_deleted"] = True

    sock.close()

    _assert_signed(state, auth_identity, envfrom, xsigner)


def main():
    # 1. Authorized: alice may sign as sender@example.com.
    print("test 1: alice as sender")
    run_transaction("alice@example.org", "<sender@example.com>", expect_signed=True)

    # 2. Authorized: alice may also sign as sales@example.com.
    print("test 2: alice as sales")
    run_transaction("alice@example.org", "<sales@example.com>", expect_signed=True)

    # 3. Unauthorized: bob is not allowed to sign as sender@example.com.
    print("test 3: bob as sender")
    run_transaction("bob@example.org", "<sender@example.com>", expect_signed=False)

    # 4. Missing authentication identity.
    print("test 4: missing auth")
    run_transaction(None, "<sender@example.com>", expect_signed=False)

    # 5. X-Signer authorized for the authenticated identity.
    print("test 5: X-Signer authorized")
    run_transaction(
        "alice@example.org",
        "<third@example.com>",
        xsigner="sender@example.com",
        expect_signed=True,
        expect_xsigner_deleted=True,
    )

    # 6. X-Signer bypass attempt: bob is not allowed to sign as sender.
    print("test 6: X-Signer bypass by bob")
    run_transaction(
        "bob@example.org",
        "<third@example.com>",
        xsigner="sender@example.com",
        expect_signed=False,
        expect_xsigner_deleted=True,
    )

    # 7. X-Signer override when envelope sender would otherwise be signed:
    #    bob is allowed for other@example.com, but not for the X-Signer sender.
    print("test 7: X-Signer override blocked")
    run_transaction(
        "bob@example.org",
        "<other@example.com>",
        xsigner="sender@example.com",
        expect_signed=False,
        expect_xsigner_deleted=True,
    )

    # 8. Case-insensitive and angle-bracket normalization.
    print("test 8: case/bracket normalization")
    run_transaction("case@example.org", "<SENDER@EXAMPLE.COM>", expect_signed=True)

    print("PASS")


if __name__ == "__main__":
    main()
