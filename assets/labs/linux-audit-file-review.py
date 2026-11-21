#!/usr/bin/env python3
"""Reassemble the bundled synthetic Linux Audit file observations."""
import argparse
from collections import defaultdict
from pathlib import Path
import re
import shlex

LINE = re.compile(r"node=([a-z0-9-]+) type=([A-Z_]+) msg=audit\(([0-9]+\.[0-9]+):([0-9]+)\): (.+)")
EXPECTED = {
    ("lab-a", "1795233600.110", "40"): ("open-succeeded", "1001", "0"),
    ("lab-b", "1795233600.110", "40"): ("open-denied", "1002", "1002"),
    ("lab-a", "1795233601.220", "41"): ("open-succeeded", "unset", "998"),
    ("lab-a", "1795233603.330", "42"): ("path-incomplete", "1001", "0"),
    ("lab-b", "1795233610.010", "43"): ("syscall-unavailable", "-", "-"),
}


def load_records(path):
    events = defaultdict(lambda: defaultdict(list))
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            node, kind, timestamp, serial, body = LINE.fullmatch(line).groups()
            fields = dict(token.split("=", 1) for token in shlex.split(body))
        except (AttributeError, ValueError) as error:
            raise ValueError(f"Unsupported fixture line {line_number}: {line}") from error
        events[(node, timestamp, serial)][kind].append(fields)
    return events


def describe(records):
    paths = records.get("PATH", [])
    calls = records.get("SYSCALL", [])
    cwd = records.get("CWD", [{}])[0].get("cwd", "-")
    path_names = [record["name"] for record in paths]
    if len(calls) != 1:
        return ("syscall-unavailable", "-", "-"), path_names, cwd

    call = calls[0]
    login_id = "unset" if call["auid"] in {"4294967295", "-1", "unset"} else call["auid"]
    indexes = sorted(int(record["item"]) for record in paths)
    if indexes != list(range(int(call["items"]))):
        decision = "path-incomplete"
    elif (call["arch"], call["syscall"]) != ("c000003e", "257"):
        decision = "unsupported-syscall"
    elif call["success"] == "yes" and int(call["exit"]) >= 0:
        decision = "open-succeeded"
    elif call["success"] == "no" and int(call["exit"]) == -13:
        decision = "open-denied"
    else:
        decision = "review-result"
    return (decision, login_id, call["euid"]), path_names, cwd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--check", action="store_true", help="check outcomes for the bundled fixture")
    args = parser.parse_args()

    outcomes = {}
    for event_id, records in load_records(args.fixture).items():
        (decision, login_id, effective_id), paths, cwd = describe(records)
        node, timestamp, serial = event_id
        outcomes[event_id] = (decision, login_id, effective_id)
        print(f"{node} audit({timestamp}:{serial}) {decision} "
              f"auid={login_id} euid={effective_id} cwd={cwd} paths={paths}")

    if args.check:
        if outcomes != EXPECTED:
            raise SystemExit("Fixture outcomes differ from the expected five events.")
        print(f"{len(outcomes)}/{len(EXPECTED)} event outcomes matched.")


if __name__ == "__main__":
    main()
