"""Compare fictional cgroup v2 memory snapshots and correlated evidence."""

import json
import sys
from pathlib import Path


COUNTERS = ("high", "max", "oom", "oom_kill")
SCOPE_FIELDS = ("node", "boot", "group", "instance", "file")
SOURCES = {"kernel_memcg", "kernel_system", "oomd"}


def parse_events(text):
    counts = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, value = line.split()
        count = int(value)
        if key in counts or count < 0:
            raise ValueError(f"invalid counter: {key}")
        counts[key] = count
    return counts


def scope(snapshot):
    return tuple(snapshot[field] for field in SCOPE_FIELDS)


def compare(before, after):
    if before is None or after is None:
        return "missing_snapshot", {}
    if scope(before) != scope(after):
        return "different_scope", {}

    earlier = parse_events(before["events"])
    later = parse_events(after["events"])
    delta = {key: later[key] - earlier[key] for key in COUNTERS
             if key in earlier and key in later}
    if any(value < 0 for value in delta.values()):
        return "nonmonotonic", {}
    return after["file"], delta


def diagnose(case):
    comparison, delta = compare(case["before"], case["after"])
    source = case["correlated_source"]
    if source not in SOURCES and source is not None:
        raise ValueError(f"unknown evidence source: {source}")
    return {
        "comparison": comparison,
        "delta": delta,
        "source": source or "unresolved",
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 linux-cgroup-memory-evidence.py CASES.json", file=sys.stderr)
        return 2
    try:
        cases = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(cases, list) or not cases:
            raise ValueError("expected a non-empty list of cases")
        results = [(case["id"], diagnose(case), case["expected"]) for case in cases]
    except (OSError, KeyError, AttributeError, TypeError, ValueError) as error:
        print(f"Unable to read cases: {error}", file=sys.stderr)
        return 2

    failures = 0
    for case_id, result, expected in results:
        same = result == expected
        failures += int(not same)
        print(f"{'PASS' if same else 'FAIL'} {case_id} {json.dumps(result)}")
        if not same:
            print(f"  expected {json.dumps(expected)}")
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
