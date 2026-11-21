"""Compare a staged renewal and the leaf selected by a simulated TLS terminator."""

import hashlib
from pathlib import Path
import shutil
import ssl
import subprocess
from tempfile import TemporaryDirectory


HOST = "inventory.example.test"


def openssl(*args, data=None, expected_failure=None):
    result = subprocess.run(["openssl", *args], input=data, capture_output=True)
    if expected_failure:
        output = result.stdout + result.stderr
        if result.returncode == 0 or expected_failure not in output:
            raise RuntimeError(f"Expected {expected_failure!r}: {output!r}")
    elif result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def make_key(path):
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", path)


def issue(directory, csr, root, root_key, label, san, serial):
    extensions = directory / f"{label}.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{san}\n",
        encoding="ascii",
    )
    leaf = directory / f"{label}.pem"
    openssl("x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key,
            "-set_serial", serial, "-days", "14", "-extfile", extensions, "-out", leaf)
    return leaf


def public_key(kind, path):
    if kind == "key":
        return openssl("pkey", "-in", path, "-pubout", "-outform", "DER")
    pem = openssl(kind, "-in", path, "-pubkey", "-noout")
    return openssl("pkey", "-pubin", "-outform", "DER", data=pem)


def peer_fingerprint(root, leaf, key):
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(cafile=root)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(leaf, key)
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname=HOST)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    endpoints = [(client, client_out, server_in), (server, server_out, client_in)]
    finished = set()
    for _ in range(32):
        for endpoint, outgoing, peer_incoming in endpoints:
            if endpoint not in finished:
                try:
                    endpoint.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                else:
                    finished.add(endpoint)
            if outgoing.pending:
                peer_incoming.write(outgoing.read())
        if len(finished) == len(endpoints):
            return hashlib.sha256(client.getpeercert(binary_form=True)).digest()
    raise RuntimeError("Memory BIO handshake did not finish")


def check(label, condition):
    if not condition:
        raise SystemExit(f"FAIL {label}")
    print(f"PASS {label}")


def main():
    if not shutil.which("openssl"):
        raise SystemExit("OpenSSL CLI was not found on PATH")
    print(openssl("version").decode().strip())
    print(f"Python TLS library: {ssl.OPENSSL_VERSION}")
    with TemporaryDirectory(prefix="cert-renewal-") as tmp:
        directory = Path(tmp)
        root_key, old_key, new_key = [directory / f"{name}.key" for name in ("root", "old", "new")]
        for key in (root_key, old_key, new_key):
            make_key(key)
        root = directory / "root.pem"
        openssl("req", "-new", "-x509", "-key", root_key, "-days", "30",
                "-subj", "/CN=Offline Renewal Lab",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", root)
        old_csr, new_csr = directory / "old.csr", directory / "new.csr"
        for key, csr in ((old_key, old_csr), (new_key, new_csr)):
            openssl("req", "-new", "-key", key, "-subj", f"/CN={HOST}",
                    "-addext", f"subjectAltName=DNS:{HOST}", "-out", csr)
            openssl("req", "-in", csr, "-noout", "-verify")
        print("PASS CSR signatures")

        old_leaf = issue(directory, old_csr, root, root_key, "old", HOST, "1")
        renewed = issue(directory, new_csr, root, root_key, "renewed", HOST, "2")
        wrong = issue(directory, new_csr, root, root_key, "wrong-name", "other.example.test", "3")

        staged_key = public_key("x509", renewed)
        check("renewal CSR, key, and leaf match",
              staged_key == public_key("req", new_csr) == public_key("key", new_key))
        check("previous key differs", staged_key != public_key("key", old_key))
        verify = ("verify", "-CAfile", root, "-no-CApath", "-no-CAstore", "-purpose", "sslserver")
        openssl(*verify, "-verify_hostname", HOST, renewed)
        print("PASS renewed leaf validates for service")
        openssl(*verify, wrong)
        openssl(*verify, "-verify_hostname", HOST, wrong, expected_failure=b"hostname mismatch")
        check("same-key signed leaf with wrong SAN is rejected",
              staged_key == public_key("x509", wrong))
        openssl("x509", "-in", renewed, "-noout", "-checkend", "86400")
        openssl("x509", "-in", renewed, "-noout", "-checkend", "1296000",
                expected_failure=b"Certificate will expire")
        print("PASS 14-day leaf expires within 15 days, with more than one day left")

        expected = hashlib.sha256(openssl("x509", "-in", renewed, "-outform", "DER")).digest()
        previous = hashlib.sha256(openssl("x509", "-in", old_leaf, "-outform", "DER")).digest()
        old_observed = peer_fingerprint(root, old_leaf, old_key)
        new_observed = peer_fingerprint(root, renewed, new_key)
        print(f"Expected renewal SHA-256: {expected.hex()}")
        print(f"Observed stale listener SHA-256: {old_observed.hex()}")
        print(f"Observed renewed listener SHA-256: {new_observed.hex()}")
        check("verified stale endpoint serves previous fingerprint",
              old_observed == previous and old_observed != expected)
        check("verified renewed endpoint serves staged fingerprint", new_observed == expected)


if __name__ == "__main__":
    main()
