#!/usr/bin/env python3
"""
signing-milter - tests/integration/miltertest/redis-tls-test.py
End-to-end Redis TLS tests for signing-milter.

Requires redis-server, redis-cli, openssl, and the signing-milter binary.
The build directory may be set with BUILD_DIR (default: ../../build).
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, "/usr/lib/python3/dist-packages")

from miltertest import client, constants

BUILD_DIR = os.environ.get("BUILD_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "..", "build"))
MILTER_BIN = os.path.join(BUILD_DIR, "signing-milter")


def run(cmd, **kwargs):
    """Run a command and return its output."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def wait_for_socket(path, timeout=15.0):
    """Wait for a Unix-domain socket to appear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.1)
    return False


class RedisTlsTest:
    def __init__(self):
        self.work = tempfile.mkdtemp(prefix="signing-milter-redis-tls-")
        self.redis_procs = []
        self.milter_procs = []
        self.ca_key = os.path.join(self.work, "ca-key.pem")
        self.ca_cert = os.path.join(self.work, "ca.pem")
        self.server_key = os.path.join(self.work, "server-key.pem")
        self.server_csr = os.path.join(self.work, "server.csr")
        self.server_cert = os.path.join(self.work, "server-cert.pem")
        self.client_key = os.path.join(self.work, "client-key.pem")
        self.client_csr = os.path.join(self.work, "client.csr")
        self.client_cert = os.path.join(self.work, "client-cert.pem")
        self.wrong_ca_key = os.path.join(self.work, "wrong-ca-key.pem")
        self.wrong_ca_cert = os.path.join(self.work, "wrong-ca.pem")
        self.wrong_client_key = os.path.join(self.work, "wrong-client-key.pem")
        self.wrong_client_cert = os.path.join(self.work, "wrong-client-cert.pem")
        self.selfsigned_key = os.path.join(self.work, "selfsigned-key.pem")
        self.selfsigned_cert = os.path.join(self.work, "selfsigned-cert.pem")

        self._generate_certs()

    def _genrsa(self, keypath):
        run(["openssl", "genpkey", "-algorithm", "RSA", "-out", keypath,
             "-pkeyopt", "rsa_keygen_bits:2048"], check=True)

    def _generate_certs(self):
        # CA
        self._genrsa(self.ca_key)
        ca_cnf = os.path.join(self.work, "ca.cnf")
        with open(ca_cnf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = test-ca\n"
                "[v3_ca]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\n"
                "basicConstraints = critical,CA:true\nkeyUsage = critical,keyCertSign,cRLSign\n"
            )
        run(["openssl", "req", "-new", "-x509", "-key", self.ca_key, "-out", self.ca_cert,
             "-days", "1", "-config", ca_cnf, "-extensions", "v3_ca", "-nodes"], check=True)

        # server cert for localhost with IP SAN
        self._genrsa(self.server_key)
        server_cnf = os.path.join(self.work, "server.cnf")
        with open(server_cnf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = localhost\n"
                "[v3_server]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n"
            )
        run(["openssl", "req", "-new", "-key", self.server_key, "-out", self.server_csr,
             "-config", server_cnf], check=True)
        run(["openssl", "x509", "-req", "-in", self.server_csr, "-CA", self.ca_cert,
             "-CAkey", self.ca_key, "-CAcreateserial", "-out", self.server_cert, "-days", "1",
             "-sha256", "-extfile", server_cnf, "-extensions", "v3_server"], check=True)

        # client cert
        self._genrsa(self.client_key)
        run(["openssl", "req", "-new", "-key", self.client_key, "-out", self.client_csr,
             "-subj", "/CN=redis-client"], check=True)
        run(["openssl", "x509", "-req", "-in", self.client_csr, "-CA", self.ca_cert,
             "-CAkey", self.ca_key, "-CAcreateserial", "-out", self.client_cert, "-days", "1",
             "-sha256"], check=True)

        # wrong CA and client cert
        self._genrsa(self.wrong_ca_key)
        run(["openssl", "req", "-new", "-x509", "-key", self.wrong_ca_key, "-out",
             self.wrong_ca_cert, "-days", "1", "-subj", "/CN=wrong-ca", "-nodes"], check=True)
        self._genrsa(self.wrong_client_key)
        wrong_client_csr = os.path.join(self.work, "wrong-client.csr")
        run(["openssl", "req", "-new", "-key", self.wrong_client_key, "-out", wrong_client_csr,
             "-subj", "/CN=wrong-client"], check=True)
        run(["openssl", "x509", "-req", "-in", wrong_client_csr, "-CA", self.wrong_ca_cert,
             "-CAkey", self.wrong_ca_key, "-CAcreateserial", "-out", self.wrong_client_cert,
             "-days", "1", "-sha256"], check=True)

        # self-signed server cert
        self._genrsa(self.selfsigned_key)
        run(["openssl", "req", "-new", "-x509", "-key", self.selfsigned_key, "-out",
             self.selfsigned_cert, "-days", "1", "-subj", "/CN=localhost", "-nodes"], check=True)

    def start_redis(self, port, cert, key, ca=None, auth_clients="no"):
        """Start redis-server with TLS on the given port."""
        conf = os.path.join(self.work, f"redis-{port}.conf")
        with open(conf, "w") as f:
            f.write("port 0\n")
            f.write(f"tls-port {port}\n")
            f.write(f"tls-cert-file {cert}\n")
            f.write(f"tls-key-file {key}\n")
            if ca:
                f.write(f"tls-ca-cert-file {ca}\n")
            f.write(f"tls-auth-clients {auth_clients}\n")
            f.write(f"pidfile {self.work}/redis-{port}.pid\n")
            f.write(f"logfile {self.work}/redis-{port}.log\n")
            f.write("daemonize yes\n")
            f.write(f"dir {self.work}\n")
        p = subprocess.Popen(["redis-server", conf])
        self.redis_procs.append(p)
        # wait for port to be reachable
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"redis-server did not start on port {port}")
        return p

    def redis_cli(self, port, *args, ca=None, cert=None, key=None, insecure=False):
        cmd = ["redis-cli", "--tls", "-p", str(port)]
        if ca:
            cmd += ["--cacert", ca]
        if cert:
            cmd += ["--cert", cert]
        if key:
            cmd += ["--key", key]
        if insecure:
            cmd += ["--insecure"]
        cmd += list(args)
        return run(cmd)

    def start_milter(self, uri, milter_work=None):
        if milter_work is None:
            milter_work = tempfile.mkdtemp(dir=self.work)
        sock = os.path.join(milter_work, "miltertest.sock")
        log = os.path.join(self.work, "milter.log")
        user = os.environ.get("USER", os.environ.get("LOGNAME", "calvin"))
        group = run(["id", "-gn"], check=True).stdout.strip()
        p = subprocess.Popen(
            [MILTER_BIN, "-u", user, "-g", group, "-c", ":relax",
             "-s", f"unix:{sock}", "-l", "-d", "7", "-r", uri, "-P", "signing-milter:"],
            stdout=open(log, "w"), stderr=subprocess.STDOUT,
        )
        self.milter_procs.append(p)
        if not wait_for_socket(sock, timeout=15.0):
            raise RuntimeError("signing-milter did not create socket")
        return sock, p

    def mailfrom_reply(self, sock_path, sender="<sender@example.com>", timeout=10.0):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            mc = client.MilterConnection(s)
            mc.optneg_mta()
            return mc.send_get(constants.SMFIC_MAIL, args=[sender])[0]

    def assert_reply(self, name, expected, actual):
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected}, got {actual}")

    def cleanup(self, keep=False):
        for p in self.milter_procs:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                p.kill()
        for p in self.redis_procs:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                p.kill()
        if not keep:
            shutil.rmtree(self.work, ignore_errors=True)

    def run(self):
        failures = []
        try:
            self._run_scenarios()
        except AssertionError as e:
            failures.append(str(e))
        except Exception as e:
            failures.append(f"exception: {e}")
        return failures

    def _run_scenarios(self):
        # Generate a valid milter signing certificate once and reuse it.
        cert_dir = os.path.join(self.work, "signing-cert")
        os.makedirs(cert_dir, exist_ok=True)
        run([os.path.join(os.path.dirname(__file__), "..", "..", "..",
             "tests", "integration", "data", "gen-test-cert.sh"), cert_dir], check=True)
        with open(os.path.join(cert_dir, "test-cert+key.pem")) as f:
            signing_pem = f.read()

        # Scenario 1: trusted CA + correct hostname + verify=peer -> success
        port1 = 16380
        self.start_redis(port1, self.server_cert, self.server_key, ca=self.ca_cert)
        self.redis_cli(port1, "HMSET", "signing-milter:sender@example.com", "pem", signing_pem, "chain", "",
                       ca=self.ca_cert).check_returncode()
        sock, _ = self.start_milter(
            f"rediss://localhost:{port1}/0?verify=peer&cacert={self.ca_cert}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("trusted CA + correct host + verify=peer", constants.SMFIR_CONTINUE, r)

        # Scenario 2: trusted CA + wrong hostname + verify=peer -> failure
        sock, _ = self.start_milter(
            f"rediss://localhost:{port1}/0?verify=peer&cacert={self.ca_cert}&verify_name=otherhost")
        r = self.mailfrom_reply(sock)
        self.assert_reply("trusted CA + wrong host + verify=peer", constants.SMFIR_TEMPFAIL, r)

        # Scenario 3: untrusted self-signed + verify=peer -> failure
        port2 = 16381
        self.start_redis(port2, self.selfsigned_cert, self.selfsigned_key, ca=self.ca_cert)
        sock, _ = self.start_milter(
            f"rediss://localhost:{port2}/0?verify=peer&cacert={self.ca_cert}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("untrusted self-signed + verify=peer", constants.SMFIR_TEMPFAIL, r)

        # Scenario 4: verify=none with self-signed -> success
        sock, _ = self.start_milter(
            f"rediss://localhost:{port2}/0?verify=none")
        r = self.mailfrom_reply(sock)
        # If no signing cert is available the milter may ACCEPT; CONTINUE is also acceptable.
        if r not in (constants.SMFIR_CONTINUE, constants.SMFIR_ACCEPT):
            raise AssertionError(f"verify=none with self-signed: expected CONTINUE/ACCEPT, got {r}")

        # Scenario 5: valid mTLS -> success
        port3 = 16382
        self.start_redis(port3, self.server_cert, self.server_key, ca=self.ca_cert, auth_clients="yes")
        sock, _ = self.start_milter(
            f"rediss://localhost:{port3}/0?verify=peer&cacert={self.ca_cert}"
            f"&cert={self.client_cert}&key={self.client_key}")
        r = self.mailfrom_reply(sock)
        if r not in (constants.SMFIR_CONTINUE, constants.SMFIR_ACCEPT):
            raise AssertionError(f"valid mTLS: expected CONTINUE/ACCEPT, got {r}")

        # Scenario 6: missing client cert on server that requires it -> failure
        sock, _ = self.start_milter(
            f"rediss://localhost:{port3}/0?verify=peer&cacert={self.ca_cert}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("missing client cert + mTLS required", constants.SMFIR_TEMPFAIL, r)

        # Scenario 7: wrong client cert -> failure
        sock, _ = self.start_milter(
            f"rediss://localhost:{port3}/0?verify=peer&cacert={self.ca_cert}"
            f"&cert={self.wrong_client_cert}&key={self.wrong_client_key}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("wrong client cert + mTLS", constants.SMFIR_TEMPFAIL, r)

        # Scenario 8: oversized MAIL FROM -> failure
        sock, _ = self.start_milter(
            f"rediss://localhost:{port1}/0?verify=peer&cacert={self.ca_cert}")
        long_sender = "<" + "a" * 1100 + "@example.com>"
        r = self.mailfrom_reply(sock, sender=long_sender)
        self.assert_reply("oversized MAIL FROM", constants.SMFIR_TEMPFAIL, r)

    def _test_stalled_tls(self):
        """TCP peer accepts but never completes TLS; milter must time out."""
        # start a silent listener on an ephemeral port
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def accept_and_hang():
            conn, _ = listener.accept()
            time.sleep(30)
            conn.close()

        import threading
        t = threading.Thread(target=accept_and_hang, daemon=True)
        t.start()

        sock, _ = self.start_milter(
            f"rediss://127.0.0.1:{port}/0?verify=none")
        t0 = time.time()
        r = self.mailfrom_reply(sock)
        elapsed = time.time() - t0
        self.assert_reply("stalled TLS handshake", constants.SMFIR_TEMPFAIL, r)
        if elapsed < 4.0 or elapsed > 7.0:
            raise AssertionError(f"stalled TLS handshake: expected ~5s timeout, got {elapsed:.2f}s")


def main():
    if not os.access(MILTER_BIN, os.X_OK):
        print(f"SKIP: signing-milter binary not found at {MILTER_BIN}")
        sys.exit(0)
    if shutil.which("redis-server") is None or shutil.which("redis-cli") is None:
        print("SKIP: redis-server/redis-cli not available")
        sys.exit(0)

    test = RedisTlsTest()
    keep = False
    try:
        failures = test.run()
        try:
            test._test_stalled_tls()
        except Exception as e:
            failures.append(str(e))
        if failures:
            keep = True
    finally:
        test.cleanup(keep=keep)

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
