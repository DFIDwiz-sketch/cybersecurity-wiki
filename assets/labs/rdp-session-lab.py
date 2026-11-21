#!/usr/bin/env python3
"""Group the supplied fictional records. Reads CSV only, with no Windows access."""

from collections import defaultdict
from pathlib import Path
import csv


def session_key(row):
    event_id = int(row["event_id"])
    if event_id in (4778, 4779):
        if not row["session_name"].lower().startswith("rdp-tcp#"):
            return None
        raw_id = row["logon_id"]
    elif event_id in (4624, 4634, 4647):
        if event_id != 4647 and row["logon_type"] != "10":
            return None
        raw_id = row["target_logon_id"]
    else:
        return None
    if not raw_id or not row["boot"] or not row["computer"]:
        return None
    return row["computer"].lower(), row["boot"], int(raw_id, 16)


def main():
    path = Path(__file__).with_name("rdp-session-events.csv")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = sorted(csv.DictReader(stream), key=lambda row: (row["time_utc"], int(row["record"])))

    groups = defaultdict(list)
    ungrouped = []
    for row in rows:
        key = session_key(row)
        if key is None:
            ungrouped.append(int(row["record"]))
        else:
            groups[key].append(row)

    actual = {key: [int(row["record"]) for row in members] for key, members in groups.items()}
    expected = {
        ("rdsh-a.example.invalid", "A1", 0x2A1): [2, 4, 6, 8, 9],
        ("rdsh-b.example.invalid", "B1", 0x2A1): [5],
        ("rdsh-a.example.invalid", "A2", 0x2A1): [11, 12],
        ("rdsh-a.example.invalid", "A2", 0x404): [13],
    }
    for key, records in expected.items():
        if actual.get(key) != records:
            raise SystemExit(f"FAIL {key}: {actual.get(key)} != {records}")
    if set(actual) != set(expected) or ungrouped != [1, 3, 7, 10]:
        raise SystemExit(f"FAIL unexpected records: {actual}, ungrouped={ungrouped}")

    for (host, boot, logon_id), members in groups.items():
        trail = " -> ".join(f'{r["record"]}:{r["event_id"]}' for r in members)
        print(f"{host} {boot} 0x{logon_id:x}: {trail}")
    print(f"Ungrouped records: {ungrouped}")
    print("5/5 grouping controls matched.")


if __name__ == "__main__":
    main()
