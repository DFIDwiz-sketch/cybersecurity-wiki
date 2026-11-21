"""Correlate synthetic AD lockout records without contacting any host."""

from datetime import datetime, timedelta
from pathlib import Path
import csv


BAD_PASSWORD = {4771: {"0X18"}, 4776: {"0XC000006A"}, 4625: {"0XC000006A"}}
WINDOW = timedelta(minutes=10)


def load_rows(path):
    unique = {}
    duplicates = 0
    with path.open(encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            row["time"] = datetime.fromisoformat(row["time"].replace("Z", "+00:00"))
            row["event"] = int(row["event"])
            # time is included since record numbers can be reused after a log reset.
            identity = (row["host"], row["channel"], row["record_id"], row["time"])
            previous = unique.get(identity)
            if previous is not None:
                if previous != row:
                    raise ValueError(f"Conflicting data for record {identity}")
                duplicates += 1
            else:
                unique[identity] = row
    return sorted(unique.values(), key=lambda row: row["time"]), duplicates


def report(rows, lockout):
    same_account = [row for row in rows if row["account"] == lockout["account"]]
    preceding = [
        row for row in same_account
        if lockout["time"] - WINDOW <= row["time"] < lockout["time"]
        and row["code"].upper() in BAD_PASSWORD.get(row["event"], set())
    ]
    subsequent = [
        row for row in same_account
        if lockout["time"] < row["time"] <= lockout["time"] + WINDOW
        and row["event"] in {4625, 4776}
        and row["code"].upper() == "0XC0000234"
    ]
    origins = sorted({row["clue"] for row in preceding if row["clue"]})
    print(f'{lockout["account"]} @ {lockout["host"]} '
          f'caller={lockout["clue"] or "missing"}')
    print(f'  prior bad-password records={len(preceding)} '
          f'clues={", ".join(origins) or "none observed"}')
    print(f'  later account-locked records={len(subsequent)}')


def main():
    path = Path(__file__).with_name("ad-lockout-cases.csv")
    rows, duplicates = load_rows(path)
    print(f'unique records={len(rows)} duplicate copies={duplicates}')
    for row in rows:
        if row["event"] == 4740:
            report(rows, row)


if __name__ == "__main__":
    main()
