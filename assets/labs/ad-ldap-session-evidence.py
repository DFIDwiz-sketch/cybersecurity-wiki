#!/usr/bin/env python3
"""Classify normalized, fictional LDAP evidence without contacting a directory."""

import argparse
import json
from pathlib import Path
import sys


def examine(case):
    bind = case["session"]
    related = {
        item["id"] for item in case["events"]
        if item.get("dc") == bind["dc"]
        and item.get("connection") == bind["connection"]
        and abs(item["time"] - bind["time"]) <= 5
    }

    if bind["transport"] == "tls" and bind["tls_status"] == "failed":
        return "tls-failed-before-bind"
    if bind["result"] == "unknown":
        if related & {3074, 3075}:
            return "cbt-audit-result-unknown"
        return "bind-result-unknown"

    if bind["result"] == "rejected":
        if bind["transport"] == "tls" and bind["auth"] == "sasl" and 3039 in related:
            return "cbt-rejection-corroborated"
        if (bind["result_code"] == 8 and 2889 in related
                and bind["transport"] == "clear"
                and (bind["auth"] == "simple" or bind["signed"] is False)):
            return "signing-rejection-corroborated"
        return "bind-rejected-cause-open"

    if bind["transport"] == "tls" and bind["auth"] == "simple":
        return "tls-simple-cbt-not-applicable"
    if bind["transport"] == "tls" and bind["auth"] == "sasl":
        if related & {3074, 3075}:
            return "accepted-with-cbt-audit"
        if bind["cbt"] == "verified":
            return "tls-sasl-cbt-verified"
        return "accepted-cbt-unconfirmed"
    if bind["transport"] == "clear" and bind["auth"] == "simple":
        return "clear-simple-accepted"
    if bind["transport"] == "clear" and bind["auth"] == "sasl":
        if bind["signed"] is True:
            return "signed-sasl-without-tls"
        if bind["signed"] is False:
            return "unsigned-sasl-accepted"
    return "accepted-protection-unconfirmed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path, default=Path(__file__).with_name(
        "ad-ldap-session-evidence-cases.json"
    ))
    args = parser.parse_args()
    try:
        cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("empty case list")
        correct = 0
        for case in cases:
            observed = examine(case)
            print(f"{case['id']}: {observed}")
            if observed == case["expected"]:
                correct += 1
            else:
                print(f"  Expected {case['expected']}", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Cannot read training fixture: {error}", file=sys.stderr)
        return 2
    print(f"{correct}/{len(cases)} LDAP evidence cases matched.")
    return 0 if correct == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
