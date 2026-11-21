"""Inspect fixed synthetic traces and run three HTTP requests on loopback."""
import json
from hashlib import sha256
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread


def interpret(row):
    # These normalized traces describe one known edge. This is not a header parser.
    signal = row["cache_status"] or ""
    if "; hit" in signal:
        return "PERSONALIZED_SHARED_HIT_REVIEW" if row["scope"] == "personalized" else "EDGE_REUSE"
    if row["upstream_status"] == 304 and row["status"] == 200:
        return "UPSTREAM_VALIDATION_WITH_DOWNSTREAM_BODY"
    if row["vary_matches"] is False:
        return "VARIANT_MISMATCH"
    if "fwd=bypass" in signal:
        return "BYPASS_AT_OBSERVED_EDGE"
    return "CACHE_PATH_UNCONFIRMED"


class LabOrigin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != "/notice":
            self.send_error(404)
            return
        # The lab accepts exactly two canned language preferences.
        language = "ko" if self.headers.get("Accept-Language") == "ko" else "en"
        text = "점검 안내\n" if language == "ko" else "Maintenance notice\n"
        body = text.encode("utf-8")
        tag = '"' + sha256(body).hexdigest() + '"'
        # Our test sends at most one strong tag. This is not a general HTTP implementation.
        unchanged = self.headers.get("If-None-Match") == tag
        self.send_response(304 if unchanged else 200)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Vary", "Accept-Language")
        self.send_header("ETag", tag)
        if not unchanged:
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Language", language)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not unchanged:
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def local_requests():
    with HTTPServer(("127.0.0.1", 0), LabOrigin) as server:
        runner = Thread(target=server.serve_forever, daemon=True)
        runner.start()
        try:
            with_connection(server.server_port)
        finally:
            server.shutdown()
            runner.join()


def with_connection(port):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", "/notice", headers={"Accept-Language": "en"})
        original = conn.getresponse()
        english = original.read()
        tag = original.getheader("ETag")
        if original.status != 200 or not english or not tag:
            raise AssertionError("Initial English response did not include content and an ETag")
        for language, expected in (("en", 304), ("ko", 200)):
            conn.request("GET", "/notice", headers={"Accept-Language": language, "If-None-Match": tag})
            response = conn.getresponse()
            body = response.read()
            if response.status != expected or response.getheader("Vary") != "Accept-Language":
                raise AssertionError(f"{language}: unexpected validation response")
            if expected == 304 and (body or response.getheader("ETag") != tag):
                raise AssertionError("Revalidation changed the tag or returned a body")
            if expected == 200 and (not body or body == english or response.getheader("ETag") == tag):
                raise AssertionError("Korean variant did not return distinct content and a new ETag")
        print("Loopback HTTP checks: 200/en, 304/en without content, 200/ko with a distinct ETag.")
    finally:
        conn.close()


def main():
    cases = json.loads(Path(__file__).with_name("http-cache-cases.json").read_text(encoding="utf-8"))
    expected = (
        "EDGE_REUSE", "UPSTREAM_VALIDATION_WITH_DOWNSTREAM_BODY", "VARIANT_MISMATCH",
        "CACHE_PATH_UNCONFIRMED", "PERSONALIZED_SHARED_HIT_REVIEW", "BYPASS_AT_OBSERVED_EDGE",
    )
    results = tuple(interpret(row) for row in cases)
    if results != expected:
        raise AssertionError(f"Unexpected worksheet results: {results}")
    for row, result in zip(cases, results):
        print(f"{row['id']}: {result}")
    print(f"{len(results)} synthetic checks passed.")
    local_requests()


if __name__ == "__main__":
    main()
