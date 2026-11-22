"""Interpret normalized, fictional endpoint isolation observations."""
import argparse
import json
from pathlib import Path


def explain(row):
    if row["status"] in {"Pending", "InProgress"}:
        return "await_enforcement_evidence"
    if row["status"] != "Succeeded":
        return "inspect_action_failure"
    if not row["match"]:
        return "wrong_device_or_path"
    if not row["observer_ok"] or row["observed_at"] is None:
        return "insufficient_observation"
    if row["observed_at"] < row["action_updated"]:
        return "before_confirmation"
    if row["observed_at"] == row["action_updated"]:
        return "time_order_uncertain"
    if row.get("released_at") is not None and row["observed_at"] >= row["released_at"]:
        return "after_release"
    if row["expected"] == "block" and row["result"] == "blocked":
        return "blocked_in_test_scope"
    if row["expected"] == "allow" and row["result"] == "completed":
        return "expected_exception"
    if row["expected"] == "block" and row["result"] == "completed":
        return "investigate_unexpected_success"
    return "inspect_observation"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    with args.cases.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            print(f'{row["case"]}: {explain(row)}')


if __name__ == "__main__":
    main()
