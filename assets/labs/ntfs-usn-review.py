"""Check the supplied NTFS worksheet with Python 3. Does not read a volume."""
import json
from pathlib import Path


def number(value):
    return int(value, 16)


def coverage(case):
    if case["saved_id"] != case["current_id"]:
        return "JOURNAL_CHANGED"
    cursor = number(case["cursor"])
    first, lowest, next_usn = map(number, (case["first"], case["lowest_valid"], case["next"]))
    if cursor < first:
        return "BEFORE_FIRST_READABLE"
    if cursor < lowest:
        return "BEFORE_CURRENT_INSTANCE"
    if cursor > next_usn:
        return "AHEAD_OF_JOURNAL"
    if cursor == next_usn:
        return "AT_CAPTURED_TAIL"
    return "WITHIN_CAPTURED_BOUNDS"


def identity(row):
    return row["volume"], row["journal"], row["file"]


def old_name_candidates(new_row, records):
    """List candidates in this small worksheet slice, without assigning causality."""
    return sorted(
        row["row"]
        for row in records
        if identity(row) == identity(new_row)
        and number(row["usn"]) < number(new_row["usn"])
        and number(row["reason"]) & 0x1000
    )


def main():
    fixture = Path(__file__).with_name("ntfs-usn-cases.json")
    data = json.loads(fixture.read_text(encoding="utf-8"))
    records = data["records"]
    by_row = {row["row"]: row for row in records}
    outcomes = {case["case"]: coverage(case) for case in data["continuity"]}
    outcomes.update({row: old_name_candidates(by_row[row], records) for row in ("R02", "R05", "R09")})
    mask = number(by_row["R06"]["reason"])
    outcomes["R06"] = [
        name for bit, name in ((1, "DATA_OVERWRITE"), (2, "DATA_EXTEND"), (0x80000000, "CLOSE"))
        if mask & bit
    ]
    expected = {
        "K01": "WITHIN_CAPTURED_BOUNDS",
        "K02": "BEFORE_FIRST_READABLE",
        "K03": "JOURNAL_CHANGED",
        "K04": "AHEAD_OF_JOURNAL",
        "K05": "BEFORE_CURRENT_INSTANCE",
        "K06": "AT_CAPTURED_TAIL",
        "R02": ["R01"],
        "R05": [],
        "R09": ["R07", "R08"],
        "R06": ["DATA_OVERWRITE", "DATA_EXTEND", "CLOSE"],
    }
    if outcomes != expected:
        raise AssertionError(f"Unexpected worksheet results: {outcomes}")
    for label, value in outcomes.items():
        print(f"{label}: {value}")
    print(f"{len(outcomes)} synthetic checks passed.")


if __name__ == "__main__":
    main()
