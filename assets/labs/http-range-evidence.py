#!/usr/bin/env python3
"""Report unique single-part 206 coverage in a synthetic viewer-facing trace."""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

BYTE_RANGE = re.compile(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)")
STRONG_ETAG = re.compile(r'"[!#-~\x80-\xff]*"')


def covered_bytes(sorted_intervals):
    """Count an inclusive interval union without counting overlaps twice."""
    count, previous_end = 0, -1
    for start, end, _ in sorted_intervals:
        count += max(0, end - max(start, previous_end + 1) + 1)
        previous_end = max(previous_end, end)
    return count


def report(rows):
    groups = defaultdict(list)
    excluded = Counter()
    for row in rows:
        status = row["status"]
        if status != 206:
            excluded[str(status)] += 1
            continue
        match = BYTE_RANGE.fullmatch(row["content_range"])
        if match is None:
            excluded["missing_or_unsupported_range"] += 1
            continue
        start, end, total = map(int, match.groups())
        if not 0 <= start <= end < total:
            excluded["invalid_interval"] += 1
            continue
        if not STRONG_ETAG.fullmatch(row["etag"]):
            excluded["no_strong_etag"] += 1
            continue
        observed = row["body_bytes"]
        if not row["completed"] or observed != end - start + 1:
            excluded["incomplete_or_size_mismatch"] += 1
            continue
        groups[row["etag"], row["encoding"], total].append((start, end, observed))

    for (etag, encoding, total), intervals in sorted(groups.items()):
        sent = sum(observed for _, _, observed in intervals)
        covered = covered_bytes(sorted(intervals))
        state = "full" if covered == total else "partial"
        print(f"  {etag} {encoding}: {sent} sent, {covered}/{total} distinct ({state})")
    for reason, count in sorted(excluded.items()):
        print(f"  excluded {reason}: {count}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="synthetic evidence JSON")
    args = parser.parse_args()
    cases = json.loads(args.trace.read_text(encoding="utf-8"))
    for scenario, rows in cases.items():
        print(scenario)
        report(rows)


if __name__ == "__main__":
    main()
