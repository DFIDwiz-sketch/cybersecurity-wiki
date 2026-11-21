#!/usr/bin/env python3
"""Compare client authentication and application authorization on loopback."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import tempfile

HOST = "127.0.0.1"
TIMEOUT = 5
REPORTER = "urn:wiki:lab:reporter"
OBSERVER = "urn:wiki:lab:observer"


def openssl(*arguments):
    result = subprocess.run(
        ["openssl", *map(str, arguments)], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"OpenSSL {arguments[0]} failed:\n{result.stderr}")
    return result.stdout.strip()


def create_ca(directory, name):
    cert = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256", "-days", 2,
        "-subj", f"/CN={name}", "-keyout", key, "-out", cert,
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    return cert, key


def create_leaf(directory, name, ca, serial, san, purpose):
    csr = directory / f"{name}.csr"
    ext = directory / f"{name}.ext"
    cert = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n",
        encoding="ascii",
    )
    openssl(
        "req", "-new", "-newkey", "rsa:2048", "-noenc",
        "-subj", f"/CN={name}", "-keyout", key, "-out", csr,
    )
    openssl(
        "x509", "-req", "-in", csr, "-CA", ca[0], "-CAkey", ca[1],
        "-set_serial", serial, "-extfile", ext, "-sha256", "-days", 2, "-out", cert,
    )
    return cert, key


def tls13(protocol):
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def tls_error(error):
    if isinstance(error, ssl.SSLCertVerificationError):
        return f"certificate verification failed ({error.verify_message})"
    return f"TLS error ({error.reason or type(error).__name__})"


def serve_once(listener, context):
    raw, _ = listener.accept()
    with raw:
        raw.settimeout(TIMEOUT)
        try:
            tls = context.wrap_socket(raw, server_side=True)
        except ssl.SSLError as error:
            return "TLS_REJECTED", tls_error(error)

        with tls, tls.makefile("rb") as stream:
            sans = tls.getpeercert().get("subjectAltName", ())
            if stream.readline(128) != b"status\n":
                raise RuntimeError("Expected one status request from the lab client")
            outcome = "ALLOWED" if sans == (("URI", REPORTER),) else "DENIED"
            tls.sendall(f"{outcome}\n".encode("ascii"))
            return outcome, f"{tls.version()}, SAN={sans}"


def run_case(server_context, server_ca, client_leaf, expected_name):
    client_context = tls13(ssl.PROTOCOL_TLS_CLIENT)
    client_context.hostname_checks_common_name = False
    client_context.load_verify_locations(cafile=server_ca)
    if client_leaf:
        client_context.load_cert_chain(*client_leaf)

    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as worker:
        listener.bind((HOST, 0))
        listener.listen(1)
        listener.settimeout(TIMEOUT)
        address = listener.getsockname()
        server_result = worker.submit(serve_once, listener, server_context)
        try:
            with socket.create_connection(address, timeout=TIMEOUT) as raw:
                with client_context.wrap_socket(raw, server_hostname=expected_name) as tls:
                    tls.sendall(b"status\n")
                    with tls.makefile("rb") as stream:
                        reply = stream.readline(128).decode("ascii").strip()
                    client = reply or "no application reply"
        except ssl.SSLError as error:
            client = tls_error(error)
        return server_result.result(), client


def main():
    if not ssl.HAS_TLSv1_3:
        raise SystemExit("This lab needs Python linked to a TLS 1.3-capable library.")
    print(f"Python {platform.python_version()} ({ssl.OPENSSL_VERSION})")
    print(openssl("version"))
    with tempfile.TemporaryDirectory(prefix="wiki-mtls-") as temporary_directory:
        directory = Path(temporary_directory)
        service_ca = create_ca(directory, "Lab Service CA")
        client_ca = create_ca(directory, "Lab Client CA")
        foreign_ca = create_ca(directory, "Lab Untrusted CA")
        server_leaf = create_leaf(directory, "service", service_ca, 1, "DNS:localhost", "serverAuth")
        reporter = create_leaf(directory, "reporter", client_ca, 1, f"URI:{REPORTER}", "clientAuth")
        observer = create_leaf(directory, "observer", client_ca, 2, f"URI:{OBSERVER}", "clientAuth")
        foreign = create_leaf(directory, "foreign", foreign_ca, 1, f"URI:{REPORTER}", "clientAuth")
        wrong_purpose = create_leaf(
            directory, "wrong-purpose", client_ca, 3, f"URI:{REPORTER}", "serverAuth"
        )

        server_context = tls13(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(*server_leaf)
        server_context.load_verify_locations(cafile=client_ca[0])
        server_context.verify_mode = ssl.CERT_REQUIRED
        server_context.num_tickets = 0

        cases = (
            ("authorized reporter", reporter, "localhost", "ALLOWED"),
            ("trusted observer", observer, "localhost", "DENIED"),
            ("missing client certificate", None, "localhost", "TLS_REJECTED"),
            ("untrusted client CA", foreign, "localhost", "TLS_REJECTED"),
            ("wrong client certificate purpose", wrong_purpose, "localhost", "TLS_REJECTED"),
            ("wrong server name", reporter, "wrong.lab.example", "TLS_REJECTED"),
        )
        for name, leaf, expected_name, expected in cases:
            (server, detail), client = run_case(server_context, service_ca[0], leaf, expected_name)
            correct_client = client == expected if expected != "TLS_REJECTED" else client not in {
                "ALLOWED", "DENIED"
            }
            if name == "wrong server name":
                correct_client = correct_client and client.startswith("certificate verification failed")
            if server != expected or not correct_client:
                raise RuntimeError(f"{name}: expected {expected}, got {server} / {client}")
            print(f"PASS {name} | server={server} ({detail}) | client={client}")
    print(f"{len(cases)}/{len(cases)} outcomes matched.")


if __name__ == "__main__":
    main()
