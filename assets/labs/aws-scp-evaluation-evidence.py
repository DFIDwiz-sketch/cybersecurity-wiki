#!/usr/bin/env python3
"""Check fictional, pre-matched AWS Organizations SCP evidence."""

import argparse
import json
from pathlib import Path

EXEMPT = {"management-account", "service-linked-role"}


def classify(case):
    principal = case["principal"]
    if principal in EXEMPT:
        return {"result": "outside-scp-scope", "reason": principal}
    if principal != "member-role":
        raise ValueError(f"unknown principal kind {principal!r}")

    levels = case["levels"]
    kinds = [level["kind"] for level in levels]
    if len(kinds) < 2 or kinds[0] != "root" or kinds[-1] != "account":
        return {"result": "insufficient-path"}
    if any(kind != "ou" for kind in kinds[1:-1]):
        return {"result": "insufficient-path"}

    denies = []
    missing_allows = []
    for level in levels:
        matching = []
        for statement in level["statements"]:
            effect = statement["effect"]
            matches = statement["matches"]
            if effect not in ("Allow", "Deny") or not isinstance(matches, bool):
                raise ValueError("expected Allow or Deny and a boolean matches value")
            if matches:
                matching.append(effect)
            if matches and effect == "Deny":
                denies.append(f'{level["id"]}/{statement["policy"]}')
        if "Allow" not in matching:
            missing_allows.append(level["id"])

    if denies:
        return {"result": "explicit-deny", "at": denies}
    if missing_allows:
        return {"result": "missing-allow", "at": missing_allows}
    return {"result": "scp-path-permits"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, nargs="?",
                        default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    try:
        cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("fixture contains no cases")
        results = [(case["id"], classify(case), case["expected"]) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")

    matched = 0
    for name, observed, expected in results:
        correct = observed == expected
        matched += correct
        status = "OK" if correct else "FAIL"
        print(f"{name} {status} {json.dumps(observed)}")
    print(f"{matched}/{len(results)} cases matched.")
    return 0 if matched == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
