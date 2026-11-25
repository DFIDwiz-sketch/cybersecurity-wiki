"""Check conclusions for normalized fictional security-group cases, offline."""

import argparse
import json
from pathlib import Path


FLOW_FIELDS = ("eni", "direction", "protocol", "src", "sport", "dst", "dport", "window")


def classify(case):
    if case["api"] == "failed":
        return "API_FAILED"

    attachment = case["attachment"]
    if attachment == "absent_in_complete_scope":
        return "UNATTACHED_IN_SCOPE"
    if attachment != "present":
        return "ATTACHMENT_UNRESOLVED"

    expected_flow = case["expected_flow"]
    observed = any(
        flow["status"] == "OK"
        and flow["action"] == "ACCEPT"
        and all(flow[field] == expected_flow[field] for field in FLOW_FIELDS)
        for flow in case["flows"]
    )

    if case.get("operation") == "revoke":
        if case.get("alternate_allow"):
            return "ALTERNATE_ALLOW"
        if observed and case.get("corroborated_existing_tracked_flow"):
            return "TRACKED_FLOW_OBSERVED"

    if observed and case.get("corroborated_app_request") and case.get("approved"):
        return "AUTHORIZED_REQUEST"
    if observed:
        return "TRAFFIC_OBSERVED"
    return "TARGET_TRAFFIC_UNRESOLVED"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    failures = 0
    for case in cases:
        result = classify(case)
        passed = result == case["expected"]
        failures += not passed
        status = "PASS" if passed else "FAIL"
        print(f"{status} {case['id']}: {result}")
        if not passed:
            print(f"  Expected: {case['expected']}")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
