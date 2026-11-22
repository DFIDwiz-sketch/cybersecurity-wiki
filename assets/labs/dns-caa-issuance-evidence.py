"""Evaluate simplified, already recorded fictional CAA lookup steps."""

import argparse
import json
from pathlib import Path


def evaluate_set(records, wildcard, issuer):
    tags = {"issue", "issuewild", "iodef"}
    if any(row["flags"] & 128 and row["tag"].lower() not in tags for row in records):
        return "unsupported_critical_property"

    tag = "issue"
    if wildcard and any(row["tag"].lower() == "issuewild" for row in records):
        tag = "issuewild"
    values = [row["value"].strip().lower() for row in records if row["tag"].lower() == tag]
    if not values:
        return "unrestricted_by_caa"
    if any(";" in value and value != ";" for value in values):
        return "parameters_not_modeled"
    if issuer.lower() in values:
        return "authorized_by_caa"
    return "issuer_not_authorized"


def classify(case):
    for step in case["lookups"]:
        if step["status"] != "ok":
            return "lookup_unresolved"
        if step["records"]:
            return evaluate_set(step["records"], case["name"].startswith("*."), case["issuer"])
    return "unrestricted_by_caa" if case["complete"] else "incomplete_evidence"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="path to the fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        results = [(case["id"], classify(case)) for case in cases]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.exit(2, f"Could not read the exercise cases: {error}\n")
    for name, result in results:
        print(f"{name}: {result}")


if __name__ == "__main__":
    main()
