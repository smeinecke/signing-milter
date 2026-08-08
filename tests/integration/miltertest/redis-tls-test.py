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
import threading
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


def ipv6_loopback_available():
    """Return True if the test environment can bind and connect to ::1."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class RedisTlsTest:
    def __init__(self):
        self.work = tempfile.mkdtemp(prefix="signing-milter-redis-tls-")
        self.redis_procs = []
        self.milter_procs = []
        self.ca_key = os.path.join(self.work, "ca-key.pem")
        self.ca_cert = os.path.join(self.work, "ca.pem")
        self.server_key = os.path.join(self.work, "server-key.pem")
        self.server_cert = os.path.join(self.work, "server-cert.pem")
        self.client_key = os.path.join(self.work, "client-key.pem")
        self.client_cert = os.path.join(self.work, "client-cert.pem")
        self.client_chain_cert = os.path.join(self.work, "client-chain.pem")
        self.intermediate_key = os.path.join(self.work, "intermediate-key.pem")
        self.intermediate_cert = os.path.join(self.work, "intermediate-cert.pem")
        self.wrong_ca_key = os.path.join(self.work, "wrong-ca-key.pem")
        self.wrong_ca_cert = os.path.join(self.work, "wrong-ca.pem")
        self.wrong_client_key = os.path.join(self.work, "wrong-client-key.pem")
        self.wrong_client_cert = os.path.join(self.work, "wrong-client-cert.pem")
        self.selfsigned_key = os.path.join(self.work, "selfsigned-key.pem")
        self.selfsigned_cert = os.path.join(self.work, "selfsigned-cert.pem")
        self.server_v6_cert = os.path.join(self.work, "server-v6-cert.pem")
        self.server_v6_key = os.path.join(self.work, "server-v6-key.pem")
        self.server_dns_cert = os.path.join(self.work, "server-dns-cert.pem")
        self.server_dns_key = os.path.join(self.work, "server-dns-key.pem")
        self.authsigningtable_txt = os.path.join(self.work, "authsigningtable")
        self.authsigningtable_cdb = os.path.join(self.work, "authsigningtable.cdb")

        self._generate_certs()

    def _genrsa(self, keypath):
        run(["openssl", "genpkey", "-algorithm", "RSA", "-out", keypath,
             "-pkeyopt", "rsa_keygen_bits:2048"], check=True)

    def _issue_cert(self, key, cert, csr, issuer_key, issuer_cert, ext=None, days="1"):
        cmd = ["openssl", "x509", "-req", "-in", csr, "-CA", issuer_cert,
               "-CAkey", issuer_key, "-CAcreateserial", "-out", cert, "-days", days, "-sha256"]
        if ext:
            cmd += ["-extfile", ext, "-extensions", "v3_ext"]
        run(cmd, check=True)

    def _generate_certs(self):
        # Root CA
        self._genrsa(self.ca_key)
        run(["openssl", "req", "-new", "-x509", "-key", self.ca_key, "-out", self.ca_cert,
             "-days", "1", "-subj", "/CN=test-ca", "-nodes"], check=True)

        # Intermediate CA (signed by root) and client cert chain
        self._genrsa(self.intermediate_key)
        intermediate_csr = os.path.join(self.work, "intermediate.csr")
        run(["openssl", "req", "-new", "-key", self.intermediate_key, "-out", intermediate_csr,
             "-subj", "/CN=test-intermediate-ca"], check=True)
        intermediate_cnf = os.path.join(self.work, "intermediate.cnf")
        with open(intermediate_cnf, "w") as f:
            f.write(
                "[v3_ext]\nsubjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = critical,CA:true,pathlen:0\n"
                "keyUsage = critical,keyCertSign,cRLSign\n"
            )
        self._issue_cert(self.intermediate_key, self.intermediate_cert, intermediate_csr,
                         self.ca_key, self.ca_cert, ext=intermediate_cnf)

        # Server cert with IP:127.0.0.1, IP:::1 and DNS:localhost
        self._genrsa(self.server_key)
        server_csr = os.path.join(self.work, "server.csr")
        server_cnf = os.path.join(self.work, "server.cnf")
        with open(server_cnf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = localhost\n"
                "[v3_ext]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage = serverAuth\n"
                "subjectAltName = DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1\n"
            )
        run(["openssl", "req", "-new", "-key", self.server_key, "-out", server_csr,
             "-config", server_cnf], check=True)
        self._issue_cert(self.server_key, self.server_cert, server_csr,
                         self.ca_key, self.ca_cert, ext=server_cnf)

        # Server cert with only IPv6 and DNS:localhost
        self._genrsa(self.server_v6_key)
        server_v6_csr = os.path.join(self.work, "server-v6.csr")
        server_v6_cnf = os.path.join(self.work, "server-v6.cnf")
        with open(server_v6_cnf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = localhost\n"
                "[v3_ext]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage = serverAuth\n"
                "subjectAltName = DNS:localhost,IP:0:0:0:0:0:0:0:1\n"
            )
        run(["openssl", "req", "-new", "-key", self.server_v6_key, "-out", server_v6_csr,
             "-config", server_v6_cnf], check=True)
        self._issue_cert(self.server_v6_key, self.server_v6_cert, server_v6_csr,
                         self.ca_key, self.ca_cert, ext=server_v6_cnf)

        # Server cert with only DNS:localhost (no IP SAN)
        self._genrsa(self.server_dns_key)
        server_dns_csr = os.path.join(self.work, "server-dns.csr")
        server_dns_cnf = os.path.join(self.work, "server-dns.cnf")
        with open(server_dns_cnf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = localhost\n"
                "[v3_ext]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost\n"
            )
        run(["openssl", "req", "-new", "-key", self.server_dns_key, "-out", server_dns_csr,
             "-config", server_dns_cnf], check=True)
        self._issue_cert(self.server_dns_key, self.server_dns_cert, server_dns_csr,
                         self.ca_key, self.ca_cert, ext=server_dns_cnf)

        # Client cert signed by intermediate, bundled with the intermediate cert
        self._genrsa(self.client_key)
        client_csr = os.path.join(self.work, "client.csr")
        run(["openssl", "req", "-new", "-key", self.client_key, "-out", client_csr,
             "-subj", "/CN=redis-client"], check=True)
        self._issue_cert(self.client_key, self.client_cert, client_csr,
                         self.intermediate_key, self.intermediate_cert)
        with open(self.client_chain_cert, "w") as f:
            f.write(open(self.client_cert).read())
            f.write(open(self.intermediate_cert).read())

        # Wrong CA and client cert
        self._genrsa(self.wrong_ca_key)
        run(["openssl", "req", "-new", "-x509", "-key", self.wrong_ca_key, "-out",
             self.wrong_ca_cert, "-days", "1", "-subj", "/CN=wrong-ca", "-nodes"], check=True)
        self._genrsa(self.wrong_client_key)
        wrong_client_csr = os.path.join(self.work, "wrong-client.csr")
        run(["openssl", "req", "-new", "-key", self.wrong_client_key, "-out", wrong_client_csr,
             "-subj", "/CN=wrong-client"], check=True)
        self._issue_cert(self.wrong_client_key, self.wrong_client_cert, wrong_client_csr,
                         self.wrong_ca_key, self.wrong_ca_cert)

        # Self-signed server cert
        self._genrsa(self.selfsigned_key)
        run(["openssl", "req", "-new", "-x509", "-key", self.selfsigned_key, "-out",
             self.selfsigned_cert, "-days", "1", "-subj", "/CN=localhost", "-nodes"], check=True)

    def start_redis(self, port, cert, key, ca=None, auth_clients="no", bind=None, protocols=None,
                    connect_host="127.0.0.1", requirepass=None, databases=None):
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
            if bind:
                f.write(f"bind {bind}\n")
            if protocols:
                f.write(f"tls-protocols {protocols}\n")
            if requirepass:
                f.write(f"requirepass {requirepass}\n")
            if databases:
                f.write(f"databases {databases}\n")
            f.write(f"pidfile {self.work}/redis-{port}.pid\n")
            f.write(f"logfile {self.work}/redis-{port}.log\n")
            f.write("daemonize no\n")
            f.write(f"dir {self.work}\n")
        p = subprocess.Popen(["redis-server", conf])
        self.redis_procs.append(p)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                if connect_host == "::1":
                    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect(("::1", port))
                    s.close()
                else:
                    with socket.create_connection((connect_host, port), timeout=1):
                        pass
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"redis-server did not start on {connect_host}:{port}")
        return p

    def redis_cli(self, port, *args, host="127.0.0.1", ca=None, cert=None, key=None, insecure=False,
                  password=None):
        cmd = ["redis-cli", "--tls", "-h", host, "-p", str(port)]
        if ca:
            cmd += ["--cacert", ca]
        if cert:
            cmd += ["--cert", cert]
        if key:
            cmd += ["--key", key]
        if insecure:
            cmd += ["--insecure"]
        if password:
            cmd += ["--pass", password]
        cmd += list(args)
        return run(cmd)

    def start_milter(self, uri, milter_work=None, password=None):
        if milter_work is None:
            milter_work = tempfile.mkdtemp(dir=self.work)
        sock = os.path.join(milter_work, "miltertest.sock")
        log = os.path.join(milter_work, "milter.log")
        user = run(["id", "-un"], check=True).stdout.strip()
        group = run(["id", "-gn"], check=True).stdout.strip()
        cmd = [
            MILTER_BIN, "-u", user, "-g", group, "-c", ":relax",
            "-s", f"unix:{sock}", "-l", "-d", "7",
            "-a", self.authsigningtable_cdb,
            "-r", uri, "-P", "signing-milter:",
        ]
        if password is not None:
            pwfile = os.path.join(milter_work, "redis-password")
            with open(pwfile, "w") as f:
                f.write(password)
            os.chmod(pwfile, 0o600)
            cmd += ["-p", pwfile]
        p = subprocess.Popen(
            cmd,
            stdout=open(log, "w"), stderr=subprocess.STDOUT,
        )
        self.milter_procs.append(p)
        if not wait_for_socket(sock, timeout=20.0):
            try:
                p.wait(timeout=2)
                rc = p.returncode
            except Exception:
                rc = "still running"
            logtxt = ""
            if os.path.exists(log):
                try:
                    with open(log) as f:
                        logtxt = f.read()
                except Exception:
                    pass
            raise RuntimeError(f"signing-milter did not create socket (rc={rc})\nlog:\n{logtxt}")
        return sock, p

    def mailfrom_reply(self, sock_path, sender="<sender@example.com>", timeout=10.0):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            mc = client.MilterConnection(s)
            mc.optneg_mta()
            mc.send_macro(constants.SMFIC_MAIL, **{"{auth_authen}": "testuser"})
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
        skips = []
        try:
            self._run_scenarios(skips)
            try:
                self._test_stalled_tls()
            except Exception as e:
                failures.append(str(e))
            try:
                self._test_tls_version(skips)
            except Exception as e:
                failures.append(str(e))
            if ipv6_loopback_available():
                try:
                    self._test_ipv6(skips)
                except Exception as e:
                    failures.append(str(e))
            else:
                skips.append("IPv6 loopback not available, skipping IPv6 tests")
        finally:
            self.cleanup(keep=bool(failures))

        if failures:
            for f in failures:
                print(f"FAIL: {f}")
            sys.exit(1)
        if skips:
            for s in skips:
                print(f"SKIP: {s}")
        print("PASS")

    def _run_scenarios(self, skips):
        cert_dir = os.path.join(self.work, "signing-cert")
        os.makedirs(cert_dir, exist_ok=True)
        run([os.path.join(os.path.dirname(__file__), "..", "..", "..",
             "tests", "integration", "data", "gen-test-cert.sh"), cert_dir], check=True)
        with open(os.path.join(cert_dir, "test-cert+key.pem")) as f:
            signing_pem = f.read()

        # signing-milter now requires an auth-signing table for Redis-backed signing.
        with open(self.authsigningtable_txt, "w") as f:
            f.write("testuser\tsender@example.com\n")
        run(["cdb", "-c", "-m", self.authsigningtable_cdb, self.authsigningtable_txt], check=True)

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

        # Scenario 5: valid mTLS with intermediate client cert chain -> success
        port3 = 16382
        self.start_redis(port3, self.server_cert, self.server_key, ca=self.ca_cert, auth_clients="yes")
        sock, _ = self.start_milter(
            f"rediss://localhost:{port3}/0?verify=peer&cacert={self.ca_cert}"
            f"&cert={self.client_chain_cert}&key={self.client_key}")
        r = self.mailfrom_reply(sock)
        if r not in (constants.SMFIR_CONTINUE, constants.SMFIR_ACCEPT):
            raise AssertionError(f"valid mTLS chain: expected CONTINUE/ACCEPT, got {r}")

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

        # Scenario 9: wrong Redis password -> AUTH rejected, signing fails
        port4 = 16386
        self.start_redis(port4, self.server_cert, self.server_key, ca=self.ca_cert,
                         requirepass="secret")
        self.redis_cli(port4, "HMSET", "signing-milter:sender@example.com", "pem", signing_pem, "chain", "",
                       ca=self.ca_cert, password="secret").check_returncode()
        sock, _ = self.start_milter(
            f"rediss://localhost:{port4}/0?verify=peer&cacert={self.ca_cert}",
            password="wrong")
        r = self.mailfrom_reply(sock)
        self.assert_reply("wrong Redis password", constants.SMFIR_TEMPFAIL, r)

        # Scenario 10: SELECT to non-existent DB -> connection/signing fails
        port5 = 16387
        self.start_redis(port5, self.server_cert, self.server_key, ca=self.ca_cert, databases=1)
        sock, _ = self.start_milter(
            f"rediss://localhost:{port5}/1?verify=peer&cacert={self.ca_cert}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("SELECT to non-existent DB", constants.SMFIR_TEMPFAIL, r)

    def _test_ipv6(self, skips):
        cert_dir = os.path.join(self.work, "signing-cert-v6")
        os.makedirs(cert_dir, exist_ok=True)
        run([os.path.join(os.path.dirname(__file__), "..", "..", "..",
             "tests", "integration", "data", "gen-test-cert.sh"), cert_dir], check=True)
        with open(os.path.join(cert_dir, "test-cert+key.pem")) as f:
            signing_pem = f.read()

        # IPv6 IP-SAN certificate succeeds with verify=peer
        port = 16383
        self.start_redis(port, self.server_v6_cert, self.server_v6_key, ca=self.ca_cert,
                         bind="127.0.0.1 ::1", connect_host="::1")
        self.redis_cli(port, "HMSET", "signing-milter:sender@example.com", "pem", signing_pem, "chain", "",
                       host="::1", ca=self.ca_cert).check_returncode()
        sock, _ = self.start_milter(
            f"rediss://[::1]:{port}/0?verify=peer&cacert={self.ca_cert}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("IPv6 IP-SAN + verify=peer", constants.SMFIR_CONTINUE, r)

        # DNS-only certificate does not validate against IPv6 literal
        port2 = 16384
        self.start_redis(port2, self.server_dns_cert, self.server_dns_key, ca=self.ca_cert,
                         bind="127.0.0.1 ::1", connect_host="::1")
        sock, _ = self.start_milter(
            f"rediss://[::1]:{port2}/0?verify=peer&cacert={self.ca_cert}")
        r = self.mailfrom_reply(sock)
        self.assert_reply("DNS-only cert vs IPv6 literal", constants.SMFIR_TEMPFAIL, r)

    def _test_tls_version(self, skips):
        """Milter must refuse TLS versions below 1.2."""
        port = 16385
        try:
            self.start_redis(port, self.server_cert, self.server_key, ca=self.ca_cert,
                             bind="127.0.0.1", protocols='"TLSv1.1"')
        except RuntimeError:
            skips.append("Redis TLSv1.1 server could not be started, skipping version test")
            return

        sock, _ = self.start_milter(
            f"rediss://127.0.0.1:{port}/0?verify=peer&cacert={self.ca_cert}")
        t0 = time.time()
        r = self.mailfrom_reply(sock)
        elapsed = time.time() - t0
        if r != constants.SMFIR_TEMPFAIL:
            raise AssertionError(f"TLSv1.1 server: expected TEMPFAIL, got {r}")
        if elapsed > 6.0:
            raise AssertionError(f"TLSv1.1 server: took too long ({elapsed:.2f}s), possible timeout fallback")

    def _test_stalled_tls(self):
        """TCP peer accepts but never completes TLS; milter must time out."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def accept_and_hang():
            conn, _ = listener.accept()
            time.sleep(30)
            conn.close()

        t = threading.Thread(target=accept_and_hang, daemon=True)
        t.start()

        sock, _ = self.start_milter(
            f"rediss://127.0.0.1:{port}/0?verify=peer&cacert={self.ca_cert}")
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
    test.run()


if __name__ == "__main__":
    main()
