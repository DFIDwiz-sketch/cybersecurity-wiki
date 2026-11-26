#!/usr/bin/env python3
"""Check HTTP digest scope on an owned 127.0.0.1 server and with local bytes."""
import argparse
import base64
import binascii
import gzip
import hashlib
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
from threading import Thread


BODY = b'{"report":"training only"}\n'
CODED = gzip.compress(BODY, mtime=0)
PART = BODY[0:8]


def digest_field(body):
    value = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{value}:"


def verify(field, body):
    if field is None:
        return "missing"
    if body is None:
        return "bytes-unavailable"
    match = re.fullmatch(r"sha-256=:([A-Za-z0-9+/=]+):", field)
    if match is None:
        return "unsupported-lab-field"
    try:
        expected = base64.b64decode(match.group(1), validate=True)
    except binascii.Error:
        return "unsupported-lab-field"
    if len(expected) != 32:
        return "unsupported-lab-field"
    same = hmac.compare_digest(expected, hashlib.sha256(body).digest())
    return "match" if same else "mismatch"


def framed(body):
    first, second = body[:11], body[11:]
    return b"".join(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n"
                    for chunk in (first, second)) + b"0\r\n\r\n"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/full":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Digest", digest_field(CODED))
            self.send_header("Repr-Digest", digest_field(CODED))
            self.end_headers()
            self.wfile.write(framed(CODED))
        elif self.path == "/part" and self.headers.get("Range") == "bytes=0-7":
            self.send_response(206)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Range", f"bytes 0-7/{len(BODY)}")
            self.send_header("Content-Length", str(len(PART)))
            self.send_header("Content-Digest", digest_field(PART))
            self.send_header("Repr-Digest", digest_field(BODY))
            self.end_headers()
            self.wfile.write(PART)
        else:
            self.send_error(404)

    def do_HEAD(self):
        if self.path != "/full":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(CODED)))
        self.send_header("Content-Digest", digest_field(b""))
        self.send_header("Repr-Digest", digest_field(CODED))
        self.end_headers()


def request(port, method, path, **headers):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, headers={"Connection": "close", **headers})
        response = conn.getresponse()
        return response.status, response.headers, response.read()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-control", action="store_true",
                        help="change a received byte before one expected-match check")
    args = parser.parse_args()
    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = server.server_port
            full_status, full, coded = request(port, "GET", "/full", **{"Accept-Encoding": "gzip"})
            part_status, part, selected = request(port, "GET", "/part", Range="bytes=0-7")
            head_status, head, empty = request(port, "HEAD", "/full", **{"Accept-Encoding": "gzip"})
        finally:
            server.shutdown()
            worker.join()

    if (full_status, part_status, head_status) != (200, 206, 200):
        parser.exit(2, "Unexpected HTTP status from the loopback lab.\n")

    # The high-level client removed HTTP chunk framing while reading coded bytes.
    test_body = bytes([coded[0] ^ 1]) + coded[1:] if args.negative_control else coded
    another_encoding = gzip.compress(BODY, mtime=1)
    checks = [
        ("A", "200 Content-Digest on received gzip bytes", verify(full["Content-Digest"], test_body), "match"),
        ("B", "200 Repr-Digest on same complete gzip variant", verify(full["Repr-Digest"], coded), "match"),
        ("C", "200 Content-Digest compared to decompressed data", verify(full["Content-Digest"], gzip.decompress(coded)), "mismatch"),
        ("D", "200 Content-Digest compared to chunk-framed bytes", verify(full["Content-Digest"], framed(coded)), "mismatch"),
        ("E", "206 Content-Digest on received bytes", verify(part["Content-Digest"], selected), "match"),
        ("F", "206 Repr-Digest checked with only the slice", verify(part["Repr-Digest"], None), "bytes-unavailable"),
        ("G", "206 Repr-Digest with complete identity variant", verify(part["Repr-Digest"], BODY), "match"),
        ("H", "HEAD Content-Digest on empty message content", verify(head["Content-Digest"], empty), "match"),
        ("I", "HEAD Repr-Digest with matching complete gzip variant", verify(head["Repr-Digest"], coded), "match"),
        ("J", "Same decoded bytes, a different gzip byte encoding", verify(full["Repr-Digest"], another_encoding), "mismatch"),
        ("K", "Optional field absent", verify(None, coded), "missing"),
        ("L", "Invalid binary digest length for lab", verify("sha-256=:YQ==:", coded), "unsupported-lab-field"),
    ]
    print(f"Loopback responses: GET {full_status}, Range {part_status}, HEAD {head_status}")
    matched = 0
    for case, label, observed, expected in checks:
        print(f"{case}: {observed} — {label}")
        if observed == expected:
            matched += 1
        else:
            print(f"  Expected {expected}")
    print(f"{matched}/{len(checks)} HTTP digest checks matched.")
    return 0 if matched == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
