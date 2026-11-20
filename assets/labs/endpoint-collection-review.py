#!/usr/bin/env python3
"""Review fictional endpoint collection manifests. No product API calls."""

import argparse
import json
from collections import Counter
from pathlib import Path


def classify(case):
    expected, result = case["expected"], case["observed"]
    for key in ("org", "client", "flow"):
        if expected[key] != result[key]:
            return "scope_mismatch", f"{key} differs"

    state = result["state"]
    if state in ("queued", "running"):
        return "pending", state
    if state in ("timeout", "error", "canceled", "limited"):
        return "incomplete", state
    if state != "complete":
        raise ValueError(f"unknown state: {state}")

    if expected["source"] != result["source"] or expected["historical_window"] != result["window"]:
        return "coverage_gap", "source or historical window differs"
    if result["coverage"] != "verified":
        return "coverage_gap", result["coverage"]

    rows, files, minimum = result["rows"], result["files"], expected["min_files"]
    if any(type(count) is not int or count < 0 for count in (rows, files, minimum)):
        raise ValueError("completed reviews require nonnegative integer counts")
    if files < minimum:
        return "missing_attachment", "expected file count not met"

    # An empty result stream need not have any SIEM document to import.
    if expected["require_delivery"] and rows > 0 and result["delivery"] != "verified":
        return "delivery_gap", "server rows exist, SIEM receipt unverified"
    if rows == 0:
        return "covered_zero", f"0 rows, {files} file(s)"
    return "results_available", f"{rows} row(s), {files} file(s)"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_name("endpoint-collection-cases.json"))
    args = parser.parse_args()
    case_id = "input"
    try:
        data = json.loads(args.fixture.read_text(encoding="utf-8"))
        counts = Counter()
        for case in data["cases"]:
            case_id = case["id"]
            status, detail = classify(case)
            counts[status] += 1
            print(f"{case_id}: {status} | {detail}")
        print(f"Reviewed: {sum(counts.values())} | Categories: {len(counts)}")
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(2, f"{args.fixture} ({case_id}): {error}\n")


if __name__ == "__main__":
    main()
