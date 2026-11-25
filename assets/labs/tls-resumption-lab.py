"""Observe TLS 1.3 full and resumed handshakes on loopback with OpenSSL 3.x."""

from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


ADDRESS = "127.0.0.1"
HOSTNAME = "localhost"
REQUEST = b"GET / HTTP/1.0\r\n\r\n"


def available_port():
    with socket.socket() as sock:
        sock.bind((ADDRESS, 0))
        return sock.getsockname()[1]


def wait_for_listener(server, log):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError("TLS server exited before listening; check loopback and OpenSSL")
        if b"ACCEPT" in log.read_bytes().splitlines():
            return
        time.sleep(0.05)
    raise RuntimeError("TLS server did not announce readiness")


def request(openssl, folder, endpoint, mode, session_args=(), hostname=HOSTNAME):
    result = subprocess.run(
        [openssl, "s_client", "-connect", endpoint, "-tls1_3",
         "-servername", hostname, "-verify_hostname", hostname,
         "-verify_return_error", "-CAfile", "cert.pem", "-no-CApath",
         "-no-CAstore", "-ign_eof", *session_args],
        cwd=folder, input=REQUEST, capture_output=True, timeout=10, check=False,
    )
    if result.returncode:
        raise RuntimeError("TLS client failed; check hostname, certificate and loopback")
    # Do not print the full transcript: OpenSSL can print session secrets.
    lines = result.stdout.splitlines()
    if not any(line.startswith(f"{mode}, TLSv1.3,".encode()) for line in lines):
        raise RuntimeError(f"Expected {mode}, TLSv1.3 in the client handshake summary")
    if not any(line.startswith(b"HTTP/1.0 200 ") for line in lines):
        raise RuntimeError("HTTP response did not contain the expected 200 status")


def run_lab(openssl, folder):
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
         "-days", "1", "-subj", "/CN=localhost", "-addext",
         "subjectAltName=DNS:localhost", "-keyout", "key.pem", "-out", "cert.pem"],
        cwd=folder, capture_output=True, timeout=15, check=True,
    )
    endpoint = f"{ADDRESS}:{available_port()}"
    log = folder / "server.log"
    with log.open("wb") as output, subprocess.Popen(
        [openssl, "s_server", "-accept", endpoint, "-cert", "cert.pem",
         "-key", "key.pem", "-tls1_3", "-www", "-naccept", "3"],
        cwd=folder, stdout=output, stderr=subprocess.STDOUT,
    ) as server:
        try:
            wait_for_listener(server, log)
            request(openssl, folder, endpoint, "New", ("-sess_out", "session.pem"))
            ticket = folder / "session.pem"
            if not ticket.is_file() or ticket.stat().st_size == 0:
                raise RuntimeError("The initial client did not save a TLS session")
            print("PASS 1: full TLS 1.3 handshake; HTTP 200; session saved")
            request(openssl, folder, endpoint, "Reused", ("-sess_in", "session.pem"))
            print("PASS 2: resumed TLS 1.3 handshake; HTTP 200")
            request(openssl, folder, endpoint, "New")
            print("PASS 3: full TLS 1.3 control with no session offered; HTTP 200")
            if server.wait(timeout=5):
                raise RuntimeError("TLS server reported a nonzero exit status")
        finally:
            if server.poll() is None:
                server.kill()


def main():
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL 3.x command-line tools are required on PATH")
    try:
        with tempfile.TemporaryDirectory(prefix="tls-resumption-") as folder:
            run_lab(openssl, Path(folder))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Lab failed: {error}") from None


if __name__ == "__main__":
    main()
