#!/usr/bin/env python3
"""Classify fictional BitLocker recovery observations without reading key material."""

import argparse
import json
from pathlib import Path


def matches_scope(record, scope):
    return all(record[key] == scope[key] for key in ("tenant", "device", "volume", "protector"))


def classify_read(audit, scope):
    if audit is None:
        return "read-unobserved"
    if not matches_scope(audit, scope):
        return "scope-mismatch"
    if audit["type"] == "metadata":
        return "metadata-only"
    if audit["type"] != "recovery-read":
        raise ValueError("unexpected audit type")
    if audit["result"] == "failure":
        return "read-failed"
    if audit["result"] != "success":
        return "read-result-unknown"
    return "approved-read-recorded" if audit["approved"] else "read-needs-review"


def classify_recovery(observation, scope):
    if observation is None:
        return "recovery-unobserved"
    if not matches_scope(observation, scope):
        return "scope-mismatch"
    return "recovery-correlated" if observation["confirmed"] else "recovery-unconfirmed"


def classify_rotation(rotation, scope):
    if rotation is None:
        return "rotation-unobserved"
    if not matches_scope(rotation, scope):
        return "scope-mismatch"
    new_id = rotation["active_replacement_id"]
    if new_id is None and rotation.get("action_result") == "accepted":
        return "rotation-request-only"
    if not new_id or new_id == scope["protector"]:
        return "replacement-unconfirmed"
    if rotation["old_protector_present"] is True:
        return "old-protector-still-present"
    if rotation["old_protector_present"] is not False:
        return "old-protector-state-unconfirmed"
    if rotation["backup_id"] is None:
        return "backup-unobserved"
    if rotation["backup_id"] != new_id:
        return "backup-id-mismatch"
    return "replacement-and-backup-verified"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    try:
        cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("fixture contains no cases")
        results = []
        for case in cases:
            scope = case["scope"]
            observed = {
                "read": classify_read(case["audit"], scope),
                "recovery": classify_recovery(case["recovery"], scope),
                "rotation": classify_rotation(case["rotation"], scope),
            }
            results.append((case["id"], observed, case["expected"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")

    matched = 0
    for case_id, actual, expected in results:
        passed = actual == expected
        matched += passed
        status = "OK" if passed else "FAIL"
        print(f"{case_id} {status} {json.dumps(actual)}")
    print(f"{matched}/{len(results)} cases matched.")
    return 0 if matched == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
