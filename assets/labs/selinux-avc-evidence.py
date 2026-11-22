#!/usr/bin/env python3
"""Join the AVC and syscall observations from the fictional workshop fixture."""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

AUDIT = re.compile(r"\bmsg=audit\(([0-9]+\.[0-9]+):([0-9]+)\):")
PERMISSIVE = re.compile(r"\bpermissive=([01])(?=\s|$)")
SUCCESS = re.compile(r"\bsuccess=(yes|no)(?=\s|$)")


def summarize(lines):
    modes = set()
    results = set()
    for line in lines:
        if line.startswith("type=AVC ") and "avc: denied {" in line:
            flag = PERMISSIVE.search(line)
            modes.add({"0": "enforcing", "1": "permissive"}[flag[1]] if flag else "unknown")
        if line.startswith("type=SYSCALL "):
            status = SUCCESS.search(line)
            if status:
                results.add({"yes": "succeeded", "no": "failed"}[status[1]])
    mode = "/".join(sorted(modes)) if modes else "none_observed"
    result = "/".join(sorted(results)) if results else "unobserved"
    return f"avc={mode} syscall={result}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    groups = defaultdict(list)
    for row in json.loads(args.fixture.read_text(encoding="utf-8")):
        match = AUDIT.search(row["record"])
        if match is None:
            raise ValueError("fixture row lacks a complete audit event ID")
        groups[row["host"], row["boot"], match[1], match[2]].append(row["record"])
    for (host, boot, timestamp, serial), lines in sorted(groups.items()):
        print(f"{host}/{boot}/{serial} audit={timestamp}:{serial} {summarize(lines)}")


if __name__ == "__main__":
    main()
