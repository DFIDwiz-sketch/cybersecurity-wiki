#!/usr/bin/env python3
"""Replay the bundled DNS cache model using a virtual clock."""
import argparse
import json
from pathlib import Path


def normalized(name):
    return name.lower().rstrip(".") + "."


class Cache:
    def __init__(self):
        self.entries = {}

    def query(self, step):
        now = step["second"]
        name = normalized(step["name"])
        qclass = step.get("class", "IN")
        qtype = step["type"]
        for key in ((name, qclass, None), (name, qclass, qtype)):
            if key not in self.entries:
                continue
            kind, expires = self.entries[key]
            if now < expires:
                return kind, "cache", expires - now
            del self.entries[key]

        upstream = step["upstream"]
        kind = upstream["kind"]
        ttl = upstream.get("failure_seconds", 0) if kind == "FAILURE" else 0
        if kind == "FAILURE" and not 1 <= ttl <= 300:
            raise ValueError("The model expects failure retention of 1 to 300 seconds.")
        if kind in {"NXDOMAIN", "NODATA"} and "soa" in upstream:
            soa = upstream["soa"]
            ttl = min(soa["record_ttl"], soa["minimum"])
        if ttl > 0:
            denied = normalized(upstream.get("terminal_name", name))
            scope = None if kind == "NXDOMAIN" else qtype
            self.entries[(denied, qclass, scope)] = (kind, now + ttl)
        return kind, "upstream", ttl or None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    total = matched = 0
    for scenario in fixture["scenarios"]:
        cache = Cache()
        last_second = -1
        for step in scenario["steps"]:
            if step["second"] < last_second:
                raise ValueError(f"Clock moved backwards in {scenario['id']}.")
            last_second = step["second"]
            actual = list(cache.query(step))
            total += 1
            matched += actual == step["expect"]
            print(f"{scenario['id']} t={last_second:>3}s {step['name']} "
                  f"{step['type']} -> {actual[0]} {actual[1]} remaining={actual[2]}")
    if args.check:
        if total != matched:
            raise SystemExit(f"{matched}/{total} steps matched.")
        print(f"{matched}/{total} simulated steps matched.")


if __name__ == "__main__":
    main()
