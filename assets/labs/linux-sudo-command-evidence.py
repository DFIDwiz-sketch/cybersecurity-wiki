"""Interpret fictional, pre-normalized sudo investigation records."""
import argparse
import json
from pathlib import Path

IDENTITY = ("host", "boot", "session", "invocation")


def same_invocation(first, second):
    return all(first.get(field) and first[field] == second.get(field) for field in IDENTITY)


def explain(case):
    decision = case["decision"]
    execution = case["execution"]
    if decision["status"] != "allowed":
        return decision["status"]
    if execution is None:
        return "allowed_execution_unknown"
    if not same_invocation(decision, execution) or execution["at"] <= decision["at"]:
        return "execution_unlinked"
    if execution["result"] == "failed":
        return "exec_failed"

    ending = case["exit"]
    if ending is None:
        return "started_exit_unknown"
    if not same_invocation(execution, ending) or ending["at"] <= execution["at"]:
        return "exit_unlinked"
    if ending["code"] != 0:
        return "command_nonzero"

    effect = case["effect"]
    if effect is None:
        return "zero_exit_effect_unknown"
    if not same_invocation(execution, effect) or effect["at"] <= execution["at"]:
        return "zero_exit_effect_unlinked"
    return "effect_confirmed" if effect["state"] == "confirmed" else "effect_unconfirmed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    with args.cases.open(encoding="utf-8") as source:
        for line in source:
            case = json.loads(line)
            print(f'{case["case"]}: {explain(case)}')


if __name__ == "__main__":
    main()
