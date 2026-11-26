"""Run five OpenSSL ALPN controls on loopback with a temporary trusted certificate."""

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SERVER_PROTOCOLS = "h2,http/1.1"


def available_loopback_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run_case(folder, protocol, offer, trace):
    port = available_loopback_port()
    address = f"127.0.0.1:{port}"
    server_args = [
        "openssl", "s_server", "-accept", address, "-naccept", "1", "-quiet",
        "-cert", "cert.pem", "-key", "key.pem", "-alpn", SERVER_PROTOCOLS, protocol,
    ]
    client_args = [
        "openssl", "s_client", "-connect", address, "-servername", "localhost",
        "-verify_hostname", "localhost", "-verify_return_error", "-CAfile", "cert.pem",
        "-no-CApath", "-no-CAstore",
        "-no_ign_eof", protocol,
    ]
    if offer is not None:
        client_args += ["-alpn", offer]
    if trace:
        client_args.append("-trace")

    # Retry only while this one-connection test server is starting.
    with subprocess.Popen(server_args, cwd=folder, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as server:
        try:
            for _ in range(20):
                result = subprocess.run(client_args, cwd=folder, input="", text=True,
                                        capture_output=True, timeout=5)
                if "Connection refused" not in result.stderr or server.poll() is not None:
                    return result
                time.sleep(0.05)
            raise RuntimeError("Loopback listener did not start.")
        finally:
            if server.poll() is None:
                server.terminate()
            _, errors = server.communicate(timeout=5)
            if errors and "Address already in use" in errors:
                print("Port contention: rerun to allocate a fresh loopback port.", file=sys.stderr)


def trace_positions(transcript):
    message = None
    locations = []
    for raw in transcript.splitlines():
        line = raw.strip()
        header = re.match(r"^(\w+), Length=\d+$", line)
        if header:
            message = header.group(1)
        if "extension_type=application_layer_protocol_negotiation(16)" in line:
            locations.append(message)
    return locations


def verify_case(folder, name, protocol, offer, expected, trace):
    result = run_case(folder, protocol, offer, trace)
    transcript = result.stdout + result.stderr
    if expected is None:
        passed = result.returncode != 0 and "alert no application protocol" in transcript.lower()
        evidence = "alert no application protocol"
    else:
        expected_wire = "TLSv1.2" if protocol == "-tls1_2" else "TLSv1.3"
        evidence = "No ALPN negotiated" if expected == "" else f"ALPN protocol: {expected}"
        passed = (
            result.returncode == 0 and evidence in result.stdout.splitlines()
            and "Verify return code: 0 (ok)" in transcript and expected_wire in transcript
        )
    if not passed:
        raise RuntimeError(f"{name} failed; OpenSSL output follows:\n{transcript}")
    print(f"PASS {name}: {evidence}")
    if trace and expected:
        reply = "ServerHello" if protocol == "-tls1_2" else "EncryptedExtensions"
        positions = trace_positions(result.stdout)
        if positions != ["ClientHello", reply]:
            raise RuntimeError(f"{name}: unexpected ALPN trace locations {positions}")
        print(f"  Endpoint trace: ClientHello offer, {reply} selection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", action="store_true",
                        help="also verify ALPN message placement using OpenSSL -trace")
    args = parser.parse_args()
    if shutil.which("openssl") is None:
        raise RuntimeError("OpenSSL 3.x must be on PATH.")
    # Keep output markers stable for assertions and human comparison.
    os.environ["LC_ALL"] = "C"
    with tempfile.TemporaryDirectory(prefix="alpn-lab-") as directory:
        folder = Path(directory)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", "key.pem", "-out", "cert.pem",
        ], cwd=folder, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
        cases = [
            ("two offers, TLS 1.3", "-tls1_3", "http/1.1,h2", "h2"),
            ("one offer, TLS 1.3", "-tls1_3", "http/1.1", "http/1.1"),
            ("no offer, TLS 1.3", "-tls1_3", None, ""),
            ("disjoint offers, TLS 1.3", "-tls1_3", "lab-only/1", None),
            ("two offers, TLS 1.2", "-tls1_2", "http/1.1,h2", "h2"),
        ]
        for case in cases:
            verify_case(folder, *case, args.trace)
    print(f"{len(cases)}/{len(cases)} ALPN controls passed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"ALPN exercise stopped: {error}", file=sys.stderr)
        sys.exit(1)
