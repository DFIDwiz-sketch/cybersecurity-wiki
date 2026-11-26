#!/usr/bin/env python3
"""Compare seven fixed outcomes over two loopback-only HTTP hops."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from math import ceil
import re
from threading import Thread

LOOPBACK = "127.0.0.1"
CLOCK = datetime(2026, 11, 27, tzinfo=timezone.utc)

# These are fixed responses. The exercise does not implement or stress-test a limiter.
ORIGIN_RESPONSES = {
    "/ok": (200, ()),
    "/origin": (429, ("45",)),
    "/maintenance": (503, ("Fri, 27 Nov 2026 00:01:30 GMT",)),
    "/missing": (429, ()),
    "/invalid": (429, ("soon",)),
    "/repeat": (429, ("30", "45")),
}
EXPECTED = {
    "/ok": (200, True, ("missing", None)),
    "/edge": (429, False, ("seconds", 30)),
    "/origin": (429, True, ("seconds", 45)),
    "/maintenance": (503, True, ("date", 90)),
    "/missing": (429, True, ("missing", None)),
    "/invalid": (429, True, ("malformed", None)),
    "/repeat": (429, True, ("repeated", None)),
}


def read_retry_after(values, received_at):
    if not values:
        return "missing", None
    if len(values) != 1:
        return "repeated", None
    value = values[0].strip()
    if re.fullmatch(r"[0-9]+", value):
        try:
            return "seconds", int(value)
        except ValueError:
            return "malformed", None
    try:
        date = parsedate_to_datetime(value)
    except (ValueError, TypeError, OverflowError):
        return "malformed", None
    if date.tzinfo is None:
        return "malformed", None
    return "date", max(0, ceil((date - received_at).total_seconds()))


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, status, fields, request_id):
        self.send_response_only(status)
        self.send_header("Date", format_datetime(CLOCK, usegmt=True))
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Lab-Request-ID", request_id)
        for field in fields:
            self.send_header("Retry-After", field)
        self.end_headers()


def request(port, path, request_id=None):
    connection = HTTPConnection(LOOPBACK, port, timeout=3)
    headers = {} if request_id is None else {"X-Lab-Request-ID": request_id}
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        response.read()
        return (response.status, response.headers.get_all("Retry-After", []),
                response.headers.get("X-Lab-Request-ID"))
    finally:
        connection.close()


@contextmanager
def serving(handler):
    with HTTPServer((LOOPBACK, 0), handler) as server:
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                        daemon=True)
        worker.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            worker.join()


def run(negative_control):
    origin_seen = set()
    gateway_decisions = {}

    class Origin(LabHandler):
        def do_GET(self):
            request_id = self.headers.get("X-Lab-Request-ID", "")
            origin_seen.add((request_id, self.path))
            status, fields = ORIGIN_RESPONSES.get(self.path, (404, ()))
            self.reply(status, fields, request_id)

    class Gateway(LabHandler):
        def do_GET(self):
            request_id = f"lab-{len(gateway_decisions) + 1}"
            upstream_attempted = self.path != "/edge"
            gateway_decisions[request_id] = upstream_attempted
            if upstream_attempted:
                status, fields, _ = request(origin_port, self.path, request_id)
            else:
                status, fields = 429, ("31" if negative_control else "30",)
            self.reply(status, fields, request_id)

    matched = 0
    with serving(Origin) as origin_port, serving(Gateway) as gateway_port:
        for route, wanted in EXPECTED.items():
            status, fields, request_id = request(gateway_port, route)
            seen = (request_id, route) in origin_seen
            upstream_attempted = gateway_decisions.get(request_id)
            observed = status, seen, read_retry_after(fields, CLOCK)
            passed = observed == wanted and upstream_attempted is seen
            matched += passed
            result = "OK" if passed else "FAIL"
            print(f"{route} {result} {request_id}: status={status} "
                  f"upstream_attempted={upstream_attempted} origin_seen={seen} "
                  f"retry={observed[2]}")
    print(f"{matched}/{len(EXPECTED)} observations matched.")
    return 0 if matched == len(EXPECTED) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-control", action="store_true")
    raise SystemExit(run(parser.parse_args().negative_control))
