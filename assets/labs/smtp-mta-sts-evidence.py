#!/usr/bin/env python3
"""Analyze the preclassified inputs from the fictional SMTP transport lab."""

import argparse
import json
from pathlib import Path


def classify(case):
    if case["live_mode"] is not None:
        source, mode = "live", case["live_mode"]
    elif case["cache_unexpired"] and case["cache_mode"] is not None:
        source, mode = "cache", case["cache_mode"]
    else:
        return "no_policy:no_sts_enforcement"

    if mode == "none":
        return f"{source}:no_sts_enforcement"
    if mode not in {"testing", "enforce"}:
        raise ValueError(f"Unrecognized MTA-STS fixture mode: {mode}")

    passed = all(case[key] is True for key in (
        "mx_matches", "starttls_offered", "tls_negotiated", "mx_certificate_valid"
    ))
    if passed:
        return f"{source}:eligible_for_smtp"
    if mode == "testing":
        return f"{source}:testing_failure"
    return f"{source}:blocked_candidate"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="Fictional JSON observations")
    args = parser.parse_args()
    try:
        exercise = json.loads(args.cases.read_text(encoding="utf-8"))
        for case in exercise["cases"]:
            print(f"{case['name']}: {classify(case)}")
        for entry in exercise["tls-report"]["policies"]:
            failures = entry["summary"]["total-failure-session-count"]
            detail_sum = sum(
                item["failed-session-count"]
                for item in entry.get("failure-details", [])
            )
            print(f"tls_report: failures={failures} detail_sum={detail_sum}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.exit(1, f"Could not analyze the fictional file: {error}\n")


if __name__ == "__main__":
    main()
