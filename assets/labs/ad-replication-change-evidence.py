#!/usr/bin/env python3
"""Compare the fictional replica observations from the AD evidence exercise."""

import argparse
import json
from pathlib import Path


ORIGIN_FIELDS = ("origin_time", "origin_invocation", "origin_usn")


def compare(first, second):
    if not first["read_ok"] or not second["read_ok"]:
        return "observation_missing"
    if any(first[key] != second[key] for key in ("object", "attribute")):
        return "scope_mismatch"

    if any(record.get(key) is None
           for record in (first, second) for key in ("version", *ORIGIN_FIELDS)):
        return "metadata_missing"
    if first["version"] != second["version"]:
        return "version_difference"
    if any(first[key] != second[key] for key in ORIGIN_FIELDS):
        return "same_version_different_origin"

    # Local USNs are intentionally excluded from cross-replica equality.
    if first.get("value_ref") is None or second.get("value_ref") is None:
        return "value_unobserved"
    if first["value_ref"] != second["value_ref"]:
        return "recheck_value_capture"
    return "same_update_and_value"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="Fictional replica observations")
    args = parser.parse_args()
    try:
        pairs = json.loads(args.cases.read_text(encoding="utf-8"))
        for pair in pairs:
            print(f"{pair['name']}: {compare(pair['first'], pair['second'])}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.exit(1, f"Could not analyze the fictional file: {error}\n")


if __name__ == "__main__":
    main()
