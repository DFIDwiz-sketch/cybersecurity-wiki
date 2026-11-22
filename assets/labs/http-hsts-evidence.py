#!/usr/bin/env python3
"""Explain dynamic HSTS matches for normalized fictional browser events."""

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def follow(events):
    policies = {}
    for event in events:
        now = event["at"]
        url = urlsplit(event["url"])
        host = url.hostname
        if event["kind"] == "response":
            if url.scheme == "https" and event["tls_ok"]:
                age = event["max_age"]
                if age == 0:
                    policies.pop(host, None)
                else:
                    policies[host] = (now + age, event["include_subdomains"])
            continue
        if url.scheme != "http":
            yield f"t={now} already_https {event['url']}"
            continue
        covered = any(
            now < expires
            and (host == domain or (include_children and host.endswith("." + domain)))
            for domain, (expires, include_children) in policies.items()
        )
        if covered:
            port = 443 if url.port == 80 else url.port
            netloc = host if port is None else f"{host}:{port}"
            https_url = urlunsplit(url._replace(scheme="https", netloc=netloc))
            yield f"t={now} upgrade {https_url}"
        else:
            yield f"t={now} no_hsts {event['url']}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    samples = json.loads(args.fixture.read_text(encoding="utf-8"))
    for name, events in samples.items():
        print(name)
        for result in follow(events):
            print(f"  {result}")


if __name__ == "__main__":
    main()
