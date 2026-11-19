#!/usr/bin/env python3
"""Compare synthetic DHCPv4 binding history with flow timestamps, offline."""

import argparse
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.utcoffset() != timedelta(0):
        raise ValueError(f"expected a UTC timestamp with an offset: {value}")
    return timestamp.astimezone(timezone.utc)


def scoped_address(event):
    return event["segment"], ipaddress.IPv4Address(event["ip"])


def classify(flow, leases):
    segment, address = scoped_address(flow)
    if not segment:
        return "unresolved", "missing segment"

    observed = utc(flow["time"])
    seconds = flow["uncertainty_seconds"]
    if type(seconds) is not int or seconds < 0:
        raise ValueError(f"{flow['id']}: clock uncertainty must be a nonnegative integer")
    margin = timedelta(seconds=seconds)
    low, high = observed - margin, observed + margin
    # A lease end is exclusive. Both flow-window bounds are inclusive.
    matches = [(start, end, lease) for start, end, lease in leases[segment, address]
               if start <= high and low < end]
    summary = ", ".join(f"{lease['id']}/{lease['client']}" for _, _, lease in matches)
    if not matches:
        return "unresolved", "no intersecting binding"
    if len(matches) > 1:
        return "ambiguous", summary

    start, end, _ = matches[0]
    if start <= low and high < end:
        return "candidate", summary
    return "unresolved", f"partial window only: {summary}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_name("dhcp-lease-cases.json"))
    args = parser.parse_args()
    try:
        data = json.loads(args.fixture.read_text(encoding="utf-8"))
        leases = defaultdict(list)
        for lease in data["leases"]:
            start, end = utc(lease["start"]), utc(lease["end"])
            if start >= end or not lease["segment"]:
                raise ValueError(f"{lease['id']}: invalid lease bounds or segment")
            leases[scoped_address(lease)].append((start, end, lease))

        counts = Counter()
        for flow in data["flows"]:
            status, detail = classify(flow, leases)
            counts[status] += 1
            print(f"{flow['id']}: {status} | {detail}")
        print(f"Candidate: {counts['candidate']} | Ambiguous: {counts['ambiguous']} "
              f"| Unresolved: {counts['unresolved']}")
    except (OSError, AttributeError, KeyError, OverflowError, TypeError, ValueError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")


if __name__ == "__main__":
    main()
