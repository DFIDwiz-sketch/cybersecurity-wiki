"""Classify normalized fictional Cloud Storage observations."""

import argparse
import json
from pathlib import Path


def classify(case):
    outcome = case["outcome"]
    if outcome == "no_event":
        return "coverage_gap" if case.get("coverage_gap") else "no_event_observed"
    if outcome == "denied":
        return "request_denied"
    if outcome != "success":
        return "operation_outcome_unresolved"

    operation = case.get("operation")
    if operation in ("list", "metadata"):
        return "listing_observed" if operation == "list" else "metadata_observed"
    if operation != "content":
        return "request_kind_unresolved"
    if case.get("same_request") is not True:
        return "content_delivery_unconfirmed"
    if case.get("full_object_verified") is True:
        return "full_receipt_confirmed"
    response_bytes = case.get("response_bytes")
    if case.get("range_response") is True and type(response_bytes) is int and response_bytes > 0:
        return "partial_content_sent"
    return "content_delivery_unconfirmed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="path to the fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        results = [(case["name"], classify(case)) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Could not read the exercise cases: {error}\n")
    for name, result in results:
        print(f"{name}: {result}")


if __name__ == "__main__":
    main()
