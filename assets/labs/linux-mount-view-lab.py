#!/usr/bin/env python3
"""Compare synthetic mountinfo snapshots and inspect an owned file on Linux."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile


def parse_mountinfo(lines):
    mounts = {}
    for line in lines:
        if not line.strip():
            continue
        fields = line.split()
        boundary = fields.index("-", 6)
        if len(fields) != boundary + 4:
            raise ValueError("unexpected mountinfo fields after separator")
        mount_id = int(fields[0])
        if mount_id in mounts:
            raise ValueError(f"duplicate mount ID {mount_id} in snapshot")
        root, target = (
            re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)
            for value in fields[3:5]
        )
        mounts[mount_id] = {
            "parent": int(fields[1]),
            "device": fields[2],
            "root": root,
            "target": target,
            "fstype": fields[boundary + 1],
        }
    return mounts


def owned_file_check():
    with tempfile.TemporaryDirectory(prefix="mount-view-") as directory:
        original = Path(directory) / "original"
        alias = Path(directory) / "alias"
        original.write_text("owned training file\n", encoding="utf-8")
        os.link(original, alias)
        with original.open("rb") as fd:
            info = Path(f"/proc/self/fdinfo/{fd.fileno()}").read_text()
            mount_id = int(next(line.split()[1] for line in info.splitlines()
                                if line.startswith("mnt_id:")))
            mounts = parse_mountinfo(Path("/proc/self/mountinfo").read_text().splitlines())
            same_object = os.path.samestat(os.fstat(fd.fileno()), alias.stat())
            found = mount_id in mounts
    print(f"Owned file: hard-link identity={same_object}, FD mount row found={found}")
    return same_object and found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="?", type=Path, default=Path(__file__).with_name(
        "linux-mount-view-cases.json"
    ))
    parser.add_argument("--fixtures-only", action="store_true",
                        help="skip the Linux procfs and hard-link observation")
    args = parser.parse_args()
    try:
        doc = json.loads(args.cases.read_text(encoding="utf-8"))
        cases = doc["cases"]
        if not cases:
            raise ValueError("empty fixture")
        passed = 0
        for case in cases:
            row = parse_mountinfo(case["mountinfo"]).get(case["mnt_id"])
            print(f"{case['id']}: {json.dumps(row, ensure_ascii=False)}")
            if row == case["expected"]:
                passed += 1
            else:
                print(f"  Expected {case['expected']}", file=sys.stderr)
        print(f"{passed}/{len(cases)} mount evidence cases matched.")
        live = args.fixtures_only or owned_file_check()
    except (OSError, ValueError, KeyError, StopIteration, TypeError) as error:
        print(f"Cannot complete observations: {error}", file=sys.stderr)
        return 2
    return 0 if passed == len(cases) and live else 1


if __name__ == "__main__":
    sys.exit(main())
