"""Compare fictional issuance and resource evidence without a cloud connection."""

import json
import sys
from datetime import datetime
from pathlib import Path


def utc_timestamp(value):
    if not value.endswith("Z"):
        raise ValueError("fixture timestamps must end in Z (UTC)")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def summarize(case):
    issuance = case["issuance"]
    call = case.get("resource_call")
    issued = [entry for entry in issuance if entry["outcome"] == "issued"]

    if issued:
        issuance_outcome = "issued"
    elif any(entry["outcome"] == "denied" for entry in issuance):
        issuance_outcome = "denied"
    else:
        issuance_outcome = "unobserved"

    candidates = []
    unknown_expirations = 0
    if call:
        call_time = utc_timestamp(call["time"])
        for entry in issued:
            if entry["target"] != call["principal"]:
                continue
            if utc_timestamp(entry["time"]) > call_time:
                continue
            expiration = entry.get("expires")
            if expiration and utc_timestamp(expiration) <= call_time:
                continue
            candidates.append(entry["event"])
            if expiration is None:
                unknown_expirations += 1

    return {
        "issuance": issuance_outcome,
        "resource_outcome": call["outcome"] if call else "unobserved",
        "recorded_delegation": call.get("delegation", []) if call else [],
        "candidate_issuance_entries": candidates,
        "candidates_without_expiration": unknown_expirations,
        "issuance_coverage": case["issuance_coverage"],
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 gcp-service-account-impersonation.py CASES.json", file=sys.stderr)
        return 2

    try:
        cases = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(cases, list) or not cases:
            raise ValueError("expected a non-empty list of cases")
        results = [(case["id"], summarize(case), case["expected"]) for case in cases]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Unable to read cases: {error}", file=sys.stderr)
        return 2

    failures = 0
    for case_id, observed, expected in results:
        matched = observed == expected
        failures += int(not matched)
        print(f"{'PASS' if matched else 'FAIL'} {case_id} {json.dumps(observed)}")
        if not matched:
            print(f"  expected {json.dumps(expected)}")
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
