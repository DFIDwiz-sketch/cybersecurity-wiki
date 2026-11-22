"""Reconstruct the normalized fictional fragments without executing their text."""

import argparse
import json
from pathlib import Path


def group_fragments(fragments):
    groups = {}
    fields = ("host", "provider", "channel", "pid", "block_id")
    for record in fragments:
        key = tuple(record[field] for field in fields)
        groups.setdefault(key, []).append(record)
    return groups


def reassemble(fragments):
    totals = set()
    parts = {}
    for record in fragments:
        number, total, content = record["number"], record["total"], record["text"]
        if type(number) is not int or type(total) is not int or not 1 <= number <= total:
            return "invalid", None
        if not isinstance(content, str):
            return "invalid", None
        totals.add(total)
        part = (record.get("protected") is True, content)
        if number in parts and parts[number] != part:
            return "conflict", None
        parts[number] = part
    if len(totals) != 1:
        return "conflict", None
    if len(parts) != totals.pop():
        return "incomplete", None
    if any(protected for protected, _ in parts.values()):
        return "protected", None
    return "complete", "".join(parts[number][1] for number in sorted(parts))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="path to the fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        for case in cases:
            groups = group_fragments(case["fragments"])
            statuses = [reassemble(parts)[0] for parts in groups.values()]
            print(f"{case['name']}: {', '.join(statuses) or 'no_records'}")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Could not read the exercise cases: {error}\n")


if __name__ == "__main__":
    main()
