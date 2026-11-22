#!/usr/bin/env python3
"""Compare adjacent observations in the fictional IPFIX export exercise."""

import argparse
import csv
from pathlib import Path


SEQUENCE_RANGE = 2**32


def counter(value):
    number = int(value)
    if not 0 <= number < SEQUENCE_RANGE:
        raise ValueError(f"Counter outside the unsigned 32-bit range: {value}")
    return number


def classify(row):
    if row["version"] != "10":
        return "unsupported_version"
    if row["previous_scope"] != row["current_scope"]:
        return "scope_changed"
    if row["previous_data_records"] == "":
        return "count_unknown"

    previous = counter(row["previous_sequence"])
    count = counter(row["previous_data_records"])
    current = counter(row["current_sequence"])
    expected = (previous + count) % SEQUENCE_RANGE
    difference = (current - expected) % SEQUENCE_RANGE

    if difference == 0:
        return "consistent"
    if difference >= SEQUENCE_RANGE // 2:
        return "ambiguous_order"
    return f"forward_gap:{difference}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="Fictional CSV observations")
    args = parser.parse_args()
    try:
        with args.cases.open(encoding="utf-8", newline="") as source:
            for row in csv.DictReader(source):
                print(f"{row['case']}: {classify(row)}")
    except (OSError, ValueError, KeyError, TypeError, csv.Error) as error:
        parser.exit(1, f"Could not analyze the exercise file: {error}\n")


if __name__ == "__main__":
    main()
