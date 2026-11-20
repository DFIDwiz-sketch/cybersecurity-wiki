#!/usr/bin/env python3
"""Locate the first unsupported stage in fictional Windows event delivery."""

import argparse
import json
from pathlib import Path


FIELDS = ("computer", "channel", "event_id", "marker")


def matches(row, expected):
    return all(row.get(field) == expected[field] for field in FIELDS)


def review(case):
    expected = case["expected"]
    if not any(matches(row, expected) for row in case["source"]):
        if case["source_coverage"] != "verified":
            return "source_coverage_gap"
        return "no_local_match"

    if not any(matches(row, expected) for row in case["collector"]):
        if case["filter"] == "excluded":
            return "subscription_excluded"
        if case["runtime"] == "transport_error":
            return "runtime_error"
        if not case["window_closed"]:
            return "delivery_window_open"
        return "collector_unconfirmed"

    checked = [row for row in case["indexed"] if row.get("marker") == expected["marker"]]
    if not checked:
        return "index_unconfirmed"
    if not all(matches(row, expected) for row in checked):
        return "index_metadata_mismatch"
    if len(checked) > 1:
        return "duplicate_index_rows"
    return "end_to_end_observed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_name("wef-delivery-cases.json"))
    args = parser.parse_args()
    try:
        data = json.loads(args.fixture.read_text(encoding="utf-8"))
        for case in data["cases"]:
            print(f"{case['id']}: {review(case)}")
        print(f"Reviewed: {len(data['cases'])}")
    except (OSError, AttributeError, KeyError, TypeError, ValueError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")


if __name__ == "__main__":
    main()
