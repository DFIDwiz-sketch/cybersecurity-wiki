#!/usr/bin/env python3
"""Correlate fictional Defender Antivirus records by endpoint and detection."""

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

FAILURES = {1118: "action-error", 1119: "critical-action-error"}
REMEDIAL_ACTIONS = {"clean", "quarantine", "remove"}
OUTCOMES = {"allow": "allowed", "block": "blocked", "no action": "no-action"}
FIELDS = ["endpoint", "detection_id", "source_utc", "record_id", "event_id",
          "action", "reported_success"]


def action_outcome(event_id, action, result):
    if event_id in FAILURES:
        return FAILURES[event_id]
    if action in OUTCOMES:
        return OUTCOMES[action]
    if action in REMEDIAL_ACTIONS and result == "yes":
        return f"reported-{action}"
    return "action-result-unconfirmed"


def summarize(events):
    first_detection = min((ts for ts, event_id, _ in events if event_id == 1116),
                          default=None)
    if first_detection is None:
        return "missing-detection"

    actions = [(ts, outcome) for ts, event_id, outcome in events if event_id != 1116]
    if not actions:
        return "detection-only"
    if any(ts < first_detection for ts, _ in actions):
        return "review-chronology"

    latest = max(ts for ts, _ in actions)
    outcomes = {outcome for ts, outcome in actions if ts == latest}
    if len(outcomes) > 1:
        return "review-conflicting-results"

    outcome = outcomes.pop()
    previous_failure = any(ts < latest and result in FAILURES.values()
                           for ts, result in actions)
    if outcome.startswith("reported-") and previous_failure:
        return f"{outcome}-after-error"
    return outcome


def main():
    default = Path(__file__).with_suffix(".csv")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, nargs="?", default=default)
    args = parser.parse_args()
    groups = defaultdict(list)
    unmatched = []

    try:
        with args.fixture.open(encoding="utf-8-sig", newline="") as fixture:
            reader = csv.DictReader(fixture)
            if reader.fieldnames != FIELDS:
                raise ValueError("unexpected CSV columns")
            for row in reader:
                timestamp = datetime.fromisoformat(row["source_utc"].replace("Z", "+00:00"))
                event_id = int(row["event_id"])
                endpoint = row["endpoint"].strip()
                detection_id = row["detection_id"].strip()
                if timestamp.utcoffset() != timedelta(0) or not endpoint:
                    raise ValueError(f"invalid UTC timestamp or endpoint on row {reader.line_num}")
                if event_id not in (1116, 1117, 1118, 1119):
                    raise ValueError(f"unexpected event ID on row {reader.line_num}")
                if not detection_id:
                    unmatched.append((endpoint, f'record-{row["record_id"]}', "missing-detection-id"))
                    continue
                outcome = action_outcome(event_id, row["action"].strip().lower(),
                                         row["reported_success"].strip().lower())
                groups[(endpoint, detection_id)].append((timestamp, event_id, outcome))
    except (OSError, TypeError, ValueError, AttributeError, csv.Error) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")

    results = [(endpoint, detection_id, summarize(events))
               for (endpoint, detection_id), events in groups.items()]
    for endpoint, detection_id, outcome in sorted(results + unmatched):
        print(f"{endpoint} {detection_id} {outcome}")


if __name__ == "__main__":
    main()
