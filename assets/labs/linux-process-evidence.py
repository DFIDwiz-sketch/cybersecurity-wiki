#!/usr/bin/env python3
"""Compare synthetic process observations or read procfs for a self-owned child."""

import argparse
import csv
import errno
import os
import subprocess
import sys
from pathlib import Path


IDENTITY_FIELDS = ("host", "boot", "pid_space", "pid", "start_ticks")
FIXTURE = Path(__file__).with_name("linux-process-observations.csv")


def compare(path):
    with path.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if not set(IDENTITY_FIELDS + ("observation",)).issubset(reader.fieldnames or ()):
            raise ValueError("required fixture columns are missing")
        rows = list(reader)
    if not rows or not all(rows[0].get(field) for field in IDENTITY_FIELDS):
        raise ValueError("the first observation must have a complete key")

    reference, *observations = rows
    missing = 0
    matches = 0
    differences = 0
    print(f"Reference: {reference['observation']}")
    for observation in observations:
        changed = [field for field in IDENTITY_FIELDS
                   if observation.get(field) and observation[field] != reference[field]]
        absent = [field for field in IDENTITY_FIELDS if not observation.get(field)]
        if changed:
            outcome = f"different key ({', '.join(changed)})"
            differences += 1
        elif absent:
            outcome = f"unresolved ({', '.join(absent)} missing)"
            missing += 1
        else:
            outcome = "same key"
            matches += 1
        print(f"{observation['observation']}: {outcome}")
    print(f"Same key: {matches} | Different key: {differences} | Unresolved: {missing}")


def read_start_ticks(proc_directory):
    descriptor = os.open("stat", os.O_RDONLY, dir_fd=proc_directory)
    with os.fdopen(descriptor, "rb") as stats:
        data = stats.read()
    # Field 2, comm, is parenthesized and can contain spaces or parentheses.
    end_of_comm = data.rfind(b")")
    if end_of_comm < 0:
        raise ValueError("proc stat is missing the closing comm delimiter")
    fields = data[end_of_comm + 1:].split()  # The first item is field 3.
    if len(fields) <= 19:
        raise ValueError("proc stat is missing field 22")
    return int(fields[19])


def observe_own_child():
    if not sys.platform.startswith("linux") or not Path("/proc/self/stat").is_file():
        raise ValueError("the live exercise requires Linux with readable /proc")
    # stdin keeps this child alive until the parent closes the pipe.
    with subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE,
    ) as child:
        descriptor = os.open(f"/proc/{child.pid}", os.O_RDONLY | os.O_DIRECTORY)
        try:
            first, second = read_start_ticks(descriptor), read_start_ticks(descriptor)
            if first != second:
                raise ValueError("the samples have different start times")
            print("Same start ticks in both reads of our running child.")
            child.stdin.close()
            if child.wait(timeout=5) != 0:
                raise ValueError("the test child did not exit normally")
            try:
                read_start_ticks(descriptor)
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ESRCH):
                    raise
                print("The open proc directory no longer provides stat after the child exits.")
            else:
                raise ValueError("expected the exited child's stat to become unavailable")
        finally:
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--fixture", type=Path, default=FIXTURE)
    choice.add_argument("--own-child", action="store_true")
    args = parser.parse_args()
    try:
        if args.own_child:
            observe_own_child()
        else:
            compare(args.fixture)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"{error}\n")


if __name__ == "__main__":
    main()
