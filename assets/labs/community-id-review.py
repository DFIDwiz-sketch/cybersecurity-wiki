#!/usr/bin/env python3
"""Review one fictional alert against synthetic flow records, offline."""

import argparse
import base64
import hashlib
import ipaddress
import json
import struct
from datetime import datetime, timedelta
from pathlib import Path


def tuple_key(record):
    endpoints = [
        (ipaddress.IPv4Address(record["src"]).packed, record["sport"]),
        (ipaddress.IPv4Address(record["dst"]).packed, record["dport"]),
    ]
    if record["protocol"] not in (6, 17):
        raise ValueError("the exercise supports only IPv4 TCP or UDP")
    return record["protocol"], *sorted(endpoints)


def community_id(record):
    protocol, (first, first_port), (last, last_port) = tuple_key(record)
    data = struct.pack("!H4s4sBBHH", record["seed"], first, last,
                       protocol, 0, first_port, last_port)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode("ascii")


def utc(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.utcoffset() != timedelta(0):
        raise ValueError(f"timestamp needs an explicit UTC offset: {value}")
    return timestamp


def review(alert, candidate, low, high):
    observed_id = candidate["community_id"]
    if not observed_id:
        return "missing_id"
    if community_id(candidate) != observed_id:
        return "inconsistent_id"
    if candidate["seed"] != alert["seed"]:
        return "different_seed"
    if observed_id != alert["community_id"] or tuple_key(candidate) != tuple_key(alert):
        return "different_tuple"
    if not candidate["scope"] or candidate["scope"] != alert["scope"]:
        return "scope_mismatch"
    start, end = utc(candidate["start"]), utc(candidate["end"])
    if start > end:
        raise ValueError("flow ends before it starts")
    if start > high or end < low:
        return "outside_window"
    return "candidate"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_name("community-id-cases.json"))
    args = parser.parse_args()
    record = "input"
    try:
        fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
        alert = fixture["alert"]
        record = alert["record"]
        if not alert["scope"] or alert["community_id"] != community_id(alert):
            raise ValueError("alert needs a valid logged ID and scope")
        seconds = fixture["tolerance_seconds"]
        if type(seconds) is not int or seconds < 0:
            raise ValueError("time tolerance must be a nonnegative integer")
        at, margin = utc(alert["at"]), timedelta(seconds=seconds)
        eligible = []
        for candidate in fixture["candidates"]:
            record = candidate["record"]
            outcome = review(alert, candidate, at - margin, at + margin)
            print(f"{record}: {outcome}")
            if outcome == "candidate":
                eligible.append(record)
        print(f"Candidates: {', '.join(eligible) or 'none'}")
        if len(eligible) > 1:
            print("Ambiguous: corroborate with packet or sensor-native evidence.")
    except (OSError, AttributeError, KeyError, OverflowError, TypeError, ValueError, struct.error) as error:
        parser.exit(2, f"{args.fixture} ({record}): {error}\n")


if __name__ == "__main__":
    main()
