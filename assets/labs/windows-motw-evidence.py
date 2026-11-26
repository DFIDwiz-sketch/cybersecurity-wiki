#!/usr/bin/env python3
"""Analyze fictional acquisition, stream creation and process observations offline."""

import argparse
import configparser
import hashlib
import json
from pathlib import Path
import re
import sys


ZONE_LABELS = {"0": "local", "1": "intranet", "2": "trusted", "3": "internet", "4": "restricted"}


def current_marker(artifact):
    status = artifact["capture"]
    if status != "read":
        return {"absent": "absent-at-collection", "unavailable": "unavailable"}[status]
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(artifact["stream"].lstrip("\ufeff"))
        if parser.defaults():
            return "uninterpretable"
        zone = parser.get("ZoneTransfer", "ZoneId", fallback="").strip()
    except configparser.Error:
        return "uninterpretable"
    return ZONE_LABELS.get(zone, "uninterpretable")


def review(case):
    artifact = case["artifact"]
    digest = hashlib.sha256(artifact["body"].encode()).hexdigest()
    creation_observed = False
    process_start_observed = False
    for event in case["events"]:
        if not (
            event["host"] == artifact["host"]
            and event["lifetime"] == artifact["lifetime"]
            and artifact["born"] <= event["time"] <= artifact["collected"]
            and event["body_sha256"].lower() == digest
        ):
            continue
        if event["id"] == 15 and re.search(
            r":zone\.identifier(?::\$data)?$", event["target"], re.IGNORECASE
        ):
            creation_observed = True
        if event["id"] == 1 and event["image_matched"] is True:
            process_start_observed = True

    return [
        current_marker(artifact),
        "stream-create-observed" if creation_observed else "stream-create-unconfirmed",
        "process-start-observed" if process_start_observed else "process-start-unconfirmed",
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path, default=Path(__file__).with_name(
        "windows-motw-evidence-cases.json"
    ))
    args = parser.parse_args()
    try:
        doc = json.loads(args.fixture.read_text(encoding="utf-8"))
        cases = doc["cases"]
        if not cases:
            raise ValueError("empty case list")
        matches = 0
        for case in cases:
            observed = review(case)
            print(f"{case['id']}: {' / '.join(observed)}")
            if observed == case["expected"]:
                matches += 1
            else:
                print(f"  Expected {' / '.join(case['expected'])}", file=sys.stderr)
        groups = {case["id"]: hashlib.sha256(case["artifact"]["body"].encode()).hexdigest()
                  for case in cases}
        for left, right in doc["equal_body_controls"]:
            same = groups[left] == groups[right]
            print(f"{left}/{right}: equal unnamed-stream SHA-256 = {same}")
            if not same:
                return 1
        print(f"{matches}/{len(cases)} MOTW evidence cases matched.")
        return 0 if matches == len(cases) else 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Cannot read training evidence: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
