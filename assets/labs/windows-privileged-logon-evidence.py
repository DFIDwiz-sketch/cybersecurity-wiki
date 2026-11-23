#!/usr/bin/env python3
"""Join normalized Windows logon, process and privilege observations offline."""

import argparse
import json
from pathlib import Path


def session_key(event, subject):
    """Return a host- and boot-scoped key for a meaningful logon context."""
    if not subject or not subject["sid"]:
        return None
    logon = int(subject["logon_id"], 16)
    if logon == 0:
        return None
    return event["host"], event["boot"], subject["sid"], logon


def summarize(records):
    assignment = next(event for event in records if event["id"] == 4672)
    key = session_key(assignment, assignment["subject"])
    if key is None:
        raise ValueError("fixture assignment has no usable logon context")

    logon = False
    tokens = set()
    calls = set()
    for event in records:
        event_id = event["id"]
        if event_id == 4688:
            if session_key(event, event.get("target")) == key:
                tokens.add(event["token_type"])
            continue
        if session_key(event, event["subject"]) != key:
            continue
        if event_id == 4624:
            logon = True
        if event_id in (4673, 4674):
            overlap = set(event["privileges"]).intersection(assignment["privileges"])
            relation = "listed" if overlap else "other_privilege"
            calls.add(f"{relation}/{event['outcome']}")

    session = "observed" if logon else "unobserved"
    process = ",".join(sorted(tokens)) or "unobserved"
    use = ",".join(sorted(calls)) or "unobserved"
    return f"logon={session} process={process} operation={use}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    samples = json.loads(args.fixture.read_text(encoding="utf-8"))
    for name, records in samples.items():
        print(f"{name}: {summarize(records)}")


if __name__ == "__main__":
    main()
