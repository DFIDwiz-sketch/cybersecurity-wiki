"""Compute NTP sample offsets for the fictional millisecond worksheet."""

import csv
import sys
from fractions import Fraction
from pathlib import Path

COLUMNS = ("case", "t1_ms", "t2_ms", "t3_ms", "t4_ms")


def evaluate(row):
    timestamps = [int(row[column]) if row[column] else None for column in COLUMNS[1:]]
    if None in timestamps:
        return "incomplete"
    t1, t2, t3, t4 = timestamps
    delay = (t4 - t1) - (t3 - t2)
    if t4 < t1 or t3 < t2 or delay < 0:
        raise ValueError("unexpected same-clock order or negative delay in worksheet")
    offset = Fraction((t2 - t1) + (t3 - t4), 2)
    return f"server_minus_client={float(offset):+.1f} ms, delay={delay} ms"


def main():
    worksheet = Path(__file__).with_suffix(".csv")
    with worksheet.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError("worksheet header differs from the download")
        for row in reader:
            if None in row or any(value is None for value in row.values()) or not row["case"]:
                raise ValueError(f"invalid CSV row on line {reader.line_num}")
            print(f'{row["case"]}: {evaluate(row)}')


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"Worksheet error: {error}")
