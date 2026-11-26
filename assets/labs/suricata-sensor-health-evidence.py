#!/usr/bin/env python3
"""Compare fictional Suricata evidence samples without contacting a sensor."""

import argparse
import json
from pathlib import Path

COUNTER_RESULTS = {
    "capture_drops": "capture-drops-increased",
    "reassembly_gaps": "reassembly-gaps-increased",
    "alert_overflow": "alert-queue-overflow-increased",
}
COUNTERS = ("decoder_packets", *COUNTER_RESULTS)


def classify_interval(case):
    before = case["before"]
    after = case["after"]
    if (before["instance"], before["scope"]) != (after["instance"], after["scope"]):
        return "baseline-changed"

    elapsed = after["time_s"] - before["time_s"]
    if elapsed <= 0 or after["uptime_s"] < before["uptime_s"]:
        return "counter-discontinuity"
    if elapsed > 2 * case["expected_interval_s"]:
        return "sampling-gap"

    deltas = {}
    for field in COUNTERS:
        start = before.get(field)
        end = after.get(field)
        if start is None or end is None:
            return "counter-unknown"
        if start < 0 or end < start:
            return "counter-discontinuity"
        deltas[field] = end - start

    changes = [label for field, label in COUNTER_RESULTS.items() if deltas[field] > 0]
    if changes:
        return "+".join(changes)
    if deltas["decoder_packets"] == 0:
        return "no-decoder-progress"
    return "no-observed-counter-increment"


def classify_delivery(case):
    if case["collector_seen"]:
        return "collector-arrival-observed"
    if not case["local_seen"]:
        return "local-event-missing"
    if case["delivery_window_elapsed"]:
        return "collector-event-missing-after-window"
    return "delivery-window-open"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_fixture = Path(__file__).with_name("suricata-sensor-health-cases.json")
    parser.add_argument("fixture", nargs="?", type=Path, default=default_fixture)
    fixture = parser.parse_args().fixture
    classifiers = {"interval": classify_interval, "delivery": classify_delivery}

    try:
        cases = json.loads(fixture.read_text(encoding="utf-8"))["cases"]
        results = [(case, classifiers[case["kind"]](case)) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"{fixture}: {error}\n")

    matched = 0
    for case, observed in results:
        expected = case["expected"]
        if observed == expected:
            print(f'{case["id"]} OK {observed}')
            matched += 1
        else:
            print(f'{case["id"]} FAIL expected {expected}, observed {observed}')

    print(f"{matched}/{len(cases)} evidence cases matched.")
    return 0 if cases and matched == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
