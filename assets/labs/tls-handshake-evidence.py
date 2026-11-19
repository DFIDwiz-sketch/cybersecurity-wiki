"""Offline TLS 1.3 exercise using Python MemoryBIO and a disposable OpenSSL certificate."""
from pathlib import Path
import ssl
import subprocess
from tempfile import TemporaryDirectory

class Peer:
    def __init__(self, context, *, server=False, hostname=None):
        self.inbound = ssl.MemoryBIO()
        self.outbound = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.inbound, self.outbound,
                                    server_side=server, server_hostname=hostname)

def transfer(sender, receiver):
    payload = sender.outbound.read()
    if payload:
        receiver.inbound.write(payload)

def handshake(client, server):
    pending = {client, server}
    for _ in range(16):
        for sender, receiver in ((client, server), (server, client)):
            if sender in pending:
                try:
                    sender.tls.do_handshake()
                    pending.remove(sender)
                except ssl.SSLWantReadError:
                    pass
            transfer(sender, receiver)
        if not pending:
            return
    raise RuntimeError("Handshake did not converge")

def configure(context):
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])

def negative(context, server_context, hostname, code, label):
    try:
        handshake(Peer(context, hostname=hostname), Peer(server_context, server=True))
    except ssl.SSLCertVerificationError as error:
        assert error.verify_code == code, error
        print(label, error.verify_message)
    else:
        raise AssertionError("Expected certificate verification failure")

def exchange(context, server_context, path, status):
    client = Peer(context, hostname="lab.example.test")
    server = Peer(server_context, server=True)
    handshake(client, server)
    assert client.tls.version() == "TLSv1.3"
    assert client.tls.selected_alpn_protocol() == "http/1.1"
    request = f"GET {path} HTTP/1.1\r\nHost: lab.example.test\r\n\r\n".encode()
    assert client.tls.write(request) == len(request)
    transfer(client, server)
    assert server.tls.read(4096) == request
    response = f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n".encode()
    assert server.tls.write(response) == len(response)
    transfer(server, client)
    assert client.tls.read(4096) == response
    print(client.tls.version(), client.tls.selected_alpn_protocol(), status)

if not ssl.HAS_TLSv1_3 or not ssl.HAS_ALPN:
    raise SystemExit("Python needs an SSL backend with TLS 1.3 and ALPN")
with TemporaryDirectory(prefix="wiki-tls-") as folder:
    cert, key = Path(folder) / "lab-cert.pem", Path(folder) / "lab-key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
        "-subj", "/CN=lab.example.test", "-addext", "subjectAltName=DNS:lab.example.test",
        "-days", "1", "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trusted.load_verify_locations(cafile=cert)
    untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for ctx in (server, trusted, untrusted):
        configure(ctx)
    exchange(trusted, server, "/health", "200 OK")
    exchange(trusted, server, "/missing", "404 Not Found")
    negative(trusted, server, "other.example.test", 62, "Wrong name:")
    negative(untrusted, server, "lab.example.test", 18, "Untrusted issuer:")
print("PASS: two authenticated HTTP exchanges and two TLS verification failures")
